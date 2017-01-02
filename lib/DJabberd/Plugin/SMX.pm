package DJabberd::Plugin::SMX;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';
use MIME::Base64;

use constant {
	NSv2 => "urn:xmpp:sm:2",
	NSv3 => "urn:xmpp:sm:3",
	NSCS => "urn:xmpp:csi:0",
	MAX_WIN => 6,
};

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::SMX - Implements XEP-0198 Stream Management extension

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0198 Stream Management ver.3 (SM3) - a part of XMPP Advanced Server
Mobile Compliance level [2016]. Additionally it adds support for XEP-0352
signaling (hence eXtended).

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::SMX>
	    resume = <timeout_secs>
	    location = <reconnect_addr:port>
	    csi = <bool>
	</Plugin>
    </VHost>

C<resume> here enables connection resumption with specified dead timeout, which is 0 hence disabled by default;

C<location> sepcifies direct ip:port where session should be restored.
Use to avoid DNS loadbalancing in clustered environment.

C<csi> enables Client State Indication support which is also off by default.
=cut

sub set_config_resume {
    my $self = shift;
    $self->{resume} = shift || 0;
}
sub set_config_csi {
    my $self = shift;
    $self->{csi} = shift;
}
sub set_config_location {
    my $self = shift;
    $self->{location} = shift;
}

sub finalize {
    my $self = shift;
    $self->{csi} ||= 0;
    $self->{resume} ||= 0;
    $self->{location} ||= '';
}

=head2 register($self, $vhost)

Register the vhost with the module.

=cut

my %cls = (
    r => 'R',
    a => 'A',
    enable => 'Enable',
);
sub register {
    my ($self,$vhost) = @_;
    my $stanza_cb = sub {
	my ($vh, $cb, $xe, $c) = @_;
	if(my $cl = $cls{$xe->element_name}) {
	    my $class = 'DJabberd::Stanza::SMX::'.$cl;
	    $logger->debug("Trying to handle with class $class");
	    return $cb->handle($class);
	}
	$cb->decline;
    };
    my $handler_cb = sub {
	my ($vh, $cb, $xe, $c) = @_;
	if($xe->isa('DJabberd::Stanza::SMX')) {
	    $logger->debug("Got SMX Stanza: ".ref($xe).$xe->as_xml);
	    $xe->process($self,$c);
	    return $cb->stop_chain;
	} else {
	    my $ctx = $self->get_ctx($c->{in_stream});
	    $ctx->{rx}++ if($ctx && ref($ctx) eq 'HASH');
	}
	$cb->decline;
    };
    my $closure_cb = sub {
	my ($vh, $cb, $c) = @_;
	return $cb->decline unless($c->{in_stream}); # TODO: garbage collect - recreate smid, delete context
	return $cb->stop_chain if($self->{resume} && $self->stash_conn($c));
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    $vhost->register_hook("HandleStanza",$stanza_cb);
    $vhost->register_hook("filter_incoming_client",$handler_cb);
    $vhost->register_hook("ConnectionClosing",$closure_cb);
    $vhost->register_hook('SendFeatures',sub {
        my ($vh, $cb, $conn) = @_;
        return $cb->stanza("<sm xmlns='".NSv2."'/><sm xmlns='".NSv3."'/>".($self->{csi} ? "<csi xmlns='".NSCS."'/>" : ''))
	    if($conn->sasl && $conn->sasl->authenticated_jid);
	$cb->decline;
    });
}

sub vh {
    return $_[0]->{vhost};
}
sub max_win { return MAX_WIN }

sub stash_conn {
    my $self = shift;
    my $conn = shift;
    my $ctx = $self->get_ctx($conn->{in_stream});
    return 0 unless($ctx && ref($ctx) eq 'HASH' && $ctx->{resume});
    # TODO: start timer for resume secs,
    # TODO: unregister user (and discard/deliver queue) om timeout
    return 1;
}

sub conn_id {
    my $self = shift;
    my $conn = shift;
    my $str = encode_base64($conn->bound_jid->as_string."\0".$conn->stream_id,'');
    $str=~s+=*$++o;
    return $str;
}

sub add_conn {
    my $self = shift;
    my $smid = shift;
    my $conn = shift;
    my $ctx = shift;
    $self->{cons}->{$smid} = $conn;
    $self->{ctxs}->{$smid} = $ctx;
}

sub del_conn {
    my $self = shift;
    my $smid = shift;
    return (delete $self->{cons}->{$smid},delete $self->{ctxs}->{$smid});
}

sub get_ctx {
    my $self = shift;
    my $smid = shift;
    return $self->{ctxs}->{$smid};
}

sub flowctl {
    my $self = shift;
    return $self->{paranoid} || 0;
}

package DJabberd::Stanza::SMX;
use base 'DJabberd::Stanza';
sub deliver {
    my $self = shift;
    my $conn = shift || $self->connection;
    # We're sending response as scalar, not ref, hence it's not handled externally
    $logger->logconfess("No connection, cannot manage nothing") unless($conn);
    $logger->debug("Writing to wire ".$self->as_xml);
    unless($conn->write($self->as_xml)) {
	$conn->log_outgoing_data("<~NUDGE~>");
	$conn->write(undef);
    }
}
sub make_response {
    my $self = shift;
    my %r2r = (
	enable => 'enabled',
	r => 'a'
    );
    return __PACKAGE__->new($self->namespace, $r2r{$self->element_name}, { %{$self->attrs} }, []);
}
package DJabberd::Stanza::SMX::Enable;
use base 'DJabberd::Stanza::SMX';

sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $conn_id = $plug->conn_id($self->connection);
    my $resp = $self->make_response;
    # this is SM context. there will be one per managed connection.
    my $ctx = { rx => 0, tx => 0, ack => 0, nack => 0, state => 'active', win => 1, last => 0, jid => $conn->bound_jid->as_string, queue => [], ns => $self->attr('{}xmlns') };
    $resp->set_attr('{}id',$conn_id);
    if($plug->{resume} && ($self->attr('{}resume')||'') eq 'true') {
	$resp->set_attr('{}max',$ctx->{max} = $plug->{resume});
	$resp->set_attr('{}location',$plug->location) if($plug->location);
    } else {
	delete $resp->attrs->{'{}resume'};
    }
    $ctx->{flowctl} = $plug->flowctl;
    # Inject sm context id into Connection object
    $conn->{in_stream} = $conn_id;
    $plug->add_conn($conn_id, $conn, $ctx);
    # Injecting a wire-wrapper to intercept stanza writes
    $conn->add_write_handler(sub {
	my ($conn, $ref, @stuff) = @_;
	# first of all store the stanza and increase tx
	push(@{$ctx->{queue}},$ref);
	$ctx->{tx}++;
	# if we're good - run flow control process
	# window is never shut by SM, only from outside (eg. CSI)
	if(!$conn->{closed} && $ctx->{win} > 0) {
	    my $d = $ctx->{tx} - $ctx->{ack};
	    # push data to the wire if window allows and we're enforcing flow control
	    if(!$ctx->{flowctl} or $d <= $ctx->{win}) {
		$conn->write($$ref);
		$logger->debug("Delivering[".$ctx->{tx}."]: ".substr($$ref,0,33)."...");
		$ctx->{last} = $ctx->{tx};
	    }
	    # if window is full - request ack (mimicking tcp sliding window)
	    if($d >= $ctx->{win}) {
		$logger->debug("Requesting ack for (ack<delta<last<=tx\@win/nack) ".$ctx->{ack}." < ".$d." < ".$ctx->{last}." <= ".$ctx->{tx}." @ ".$ctx->{win}." / ".$ctx->{nack});
		$conn->write("<r xmlns='".$ctx->{ns}."'/>") or $conn->write(undef); # enforce if queued
		# if it's more than full - try to narrow down the window
		$ctx->{win}-- if($ctx->{win}>1 && $ctx->{nack}>0);
		# and pump the nack pressure
		$ctx->{nack}++ if($d > $ctx->{win});
	    }
	}
    });
    $logger->debug("Attempting to deliver SM response: ".$resp->as_xml);
    # now signal the other side we're ready
    $resp->deliver($conn);
}

package DJabberd::Stanza::SMX::R;
use base 'DJabberd::Stanza::SMX';

sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = $plug->get_ctx($conn->{in_stream});
    return unless($ctx);
    my $resp = $self->make_response;
    $resp->set_attr('{}h',$ctx->{rx});
    $resp->deliver($conn);
}

package DJabberd::Stanza::SMX::A;
use base 'DJabberd::Stanza::SMX';

sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = $plug->get_ctx($conn->{in_stream});
    return unless($ctx);
    my $h = $self->attr('{}h');
    # we MAY error-close the stream, so let just do it as it may corrupt the queue and basically means we're not in sync with the other side anyway
    $logger->logcroak("Invalid SM ACK: $h </> for ".$ctx->{ack}." last ".$ctx->{last}) unless(defined $h && $ctx->{ack} <= $h && $h <= $ctx->{last});
    # ack stepped up, decrease nack pressure
    $ctx->{nack}-- if($ctx->{nack}>0 && $h > $ctx->{ack});
    # discard acked events from the queue
    while($ctx->{ack} < $h) {
	$ctx->{ack}++;
	shift(@{$ctx->{queue}});
    }
    $logger->debug("Advancing queue to $h, ".scalar(@{$ctx->{queue}})." items remain");
    # increase the window if we're not under pressure and no backlog
    if($ctx->{nack} == 0 && $ctx->{ack} == $ctx->{tx} && $ctx->{win} < $plug->max_win) {
	$ctx->{win}++;
    } elsif($ctx->{last} < $ctx->{tx} && $ctx->{win} > 0) {
	# push some of the backlog up to the window and ask for ack
	my $ceil = $ctx->{tx} - $ctx->{ack}; # should equal to scalar(@{$ctx->{queue}})
	$ceil = $ctx->{win} if($ceil > $ctx->{win});
	for($h = $ctx->{last}-$ctx->{ack}; $h < $ceil; $h++) {
	    $conn->write(${$ctx->{queue}->[$h]});
	    $ctx->{last}++;
	}
	$conn->write("<r xmlns='".$ctx->{ns}."'/>") or $conn->write(undef);
	$logger->debug("Flushed $h items from the queue, waiting for ack...");
    }
}

1;
