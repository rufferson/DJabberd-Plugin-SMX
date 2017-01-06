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
    resume => 'Resume',
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
	$logger->debug('Callback for stream '.$c->stream_id.' ['.$c->{id}.'] '.$c->{in_stream}.' for '.($c->bound_jid||'<null>'));
	return $cb->stop_chain if($c->{in_stream} && $self->{resume} && $self->stash_conn($c));
	# garbage collect - recreate smid, delete con/ctx - requires stream_id and bound_jid
	$self->gc_conn($c);
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
    $logger->debug("Attempting to stash the conn ".$conn->{id}." with ".$conn->{in_stream}." and ".($ctx || '<null_ctx>'));
    return 0 unless($ctx && ref($ctx) eq 'HASH' && $ctx->{resume});
    # release resources and remove from event loop
    DJabberd::Connection::close($conn); # damn I hate these types of calls but there's no other way
    # TODO: start timer for resume secs,
    # TODO: unregister user (and discard/deliver queue) om timeout
    return 1;
}

sub gc_conn {
    my $self = shift;
    my $conn = shift;
    return unless($conn->bound_jid && $conn->stream_id);
    my $smid = $conn->{in_stream};
    $smid = $self->conn_id($conn) unless($smid && $self->{cons}->{$smid} && $self->{cons}->{$smid} == $conn);
    my ($con,$ctx) = $self->cleanup($smid);
    $logger->error("Cannot cleanup resources for connection ".$conn->{id}." with smid $smid") unless($ctx && ref($ctx));
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
    $self->{ctxs}->{$smid} = $ctx if($ctx);
}

sub get_conn {
    my $self = shift;
    my $smid = shift;
    return $self->{cons}->{$smid};
}

sub del_conn {
    my $self = shift;
    my $smid = shift;
    return delete $self->{cons}->{$smid};
}

sub cleanup {
    my $self = shift;
    my $smid = shift;
    my @ret = (delete $self->{cons}->{$smid},delete $self->{ctxs}->{$smid});
    # Get rid of closures
    $ret[0]->{write_handlers} = [];
    #$ret[1]->{next}->cancel if($ret[1]->{next});
    return @ret;
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
    $conn->log_outgoing_data($self->as_xml);
    unless($conn->write($self->as_xml)) {
	$conn->log_outgoing_data("<~NUDGE~>");
	$conn->write(undef);
    }
}
sub make_response {
    my $self = shift;
    my %r2r = (
	enable => 'enabled',
	resume => 'resumed',
	r => 'a'
    );
    return __PACKAGE__->new($self->namespace, $r2r{$self->element_name}, { %{$self->attrs} }, []);
}
sub reply_error {
    my $self = shift;
    my $cause = shift;
    my $reason = shift;
    my $xml = "<failed xmlns='".$self->attr('{}xmlns')."'><$cause xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>";
    $self->connection->log_outgoing_data($xml);
    $self->connection->write($xml);
    $logger->error($reason) if($reason);
}
package DJabberd::Stanza::SMX::Enable;
use base 'DJabberd::Stanza::SMX';

sub validate {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $conn_id = shift;
    unless($conn->{in_stream} && !$conn->{closed} && $conn->stream_id && $conn->bound_jid && !$plug->get_ctx($conn_id) && !$plug->get_ctx($conn->{in_stream})) {
	$self->reply_error("unexpected-request",
	    "Cannot enable SM for this connection: streamOpen:".$conn->{in_stream}."; ID:".$conn->stream_id."; bound:".$conn->bound_jid->as_string."; closed:".$conn->closed);
	return 0;
    }
    return 1;
}
sub make_response {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = shift;
    my $smid = shift;
    my $resp = $self->SUPER::make_response();
    $resp->set_attr('{}id',$smid);
    my $resume = $self->attr('{}resume')||'';
    if($plug->{resume} && ($resume eq 'true' || $resume eq '1')) {
	$resp->set_attr('{}max',$ctx->{resume} = $plug->{resume});
	$resp->set_attr('{}location',$plug->{location}) if($plug->{location});
    } else {
	delete $resp->attrs->{'{}resume'};
    }
    return $resp;
}
sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    # these params are passed only from super calls when context is already set and validated
    my $ctx = shift;
    my $conn_id = shift || $plug->conn_id($self->connection);
    unless($ctx && ref($ctx) eq 'HASH') {
	return unless($self->validate($plug,$conn,$conn_id));
	# Initialize brand new one unless it was passed to us
	$ctx = { rx => 0, tx => 0, ack => 0, nack => 0, win => 1, last => 0, state => 'active', jid => $conn->bound_jid->as_string, queue => [], ns => $self->attr('{}xmlns') };
	$ctx->{flowctl} = $plug->flowctl;
	# Inject sm context id into Connection object
	$plug->add_conn($conn_id, $conn, $ctx);
    }
    $conn->{in_stream} = $conn_id;
    # Injecting a wire-wrapper to intercept stanza writes
    $conn->add_write_handler(sub {
	my ($conn, $ref, @stuff) = @_;
	# first of all store the stanza and increase tx
	push(@{$ctx->{queue}},$ref);
	$ctx->{tx}++;
	# if we're good - run flow control process
	# window is never shut by SM, only from outside (eg. CSI)
	if(!$conn->{closed} && $ctx->{win} > 0) {
	    # discard next ack timer if it hasn't fired
	    #$ctx->{next}->cancel if($ctx->{next});
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
		my $xml = "<r xmlns='".$ctx->{ns}."'/>";
		$conn->log_outgoing_data($xml);
		$conn->write($xml) or $conn->write(undef); # enforce if queued
		# if it's more than full - try to narrow down the window
		$ctx->{win}-- if($ctx->{win}>1 && $ctx->{nack}>0);
		# and pump the nack pressure
		$ctx->{nack}++ if($d > $ctx->{win});
	    #} else {
	    #	# not sure we need it, resumption will provide latest ack anyway
	    #	$ctx->{next} = Danga::Socket::AddTimer(3,sub {
	    #	    delete $ctx->{next};
	    #	    $logger->debug("Requesting ack for (ack<delta<last<=tx\@win/nack) ".$ctx->{ack}." < ".$d." < ".$ctx->{last}." <= ".$ctx->{tx}." @ ".$ctx->{win}." / ".$ctx->{nack});
	    #	    $conn->write("<r xmlns='".$ctx->{ns}."'/>") or $conn->write(undef); # enforce if queued
	    #	});
	    }
	}
    });
    # now signal the other side we're ready
    my $resp = $self->make_response($plug,$conn,$ctx,$conn_id);
    $logger->debug("Attempting to deliver SM response: ".$resp->as_xml);
    $resp->deliver($conn);
}


package DJabberd::Stanza::SMX::Resume;
use base 'DJabberd::Stanza::SMX::Enable';

sub validate {
    # validated inline
    return 1;
}
sub make_response {
    return DJabberd::Stanza::SMX::R::make_response(@_);
}
sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    unless($plug->{resume}) {
	$self->reply_error('feature-not-implemented',
	    "Cannot resume SM for this connection: Stream resumption is not enabled for this plugin in VHost ".$plug->vh->name);
	return;
    }
    unless($conn->{in_stream} && $conn->stream_id && !$conn->bound_jid && !$conn->{closed}) {
	$self->reply_error('unexpected-request',
	    "Cannot resume SM for this connection: streamOpen:".$conn->{in_stream}."; ID:".$conn->stream_id."; bound:".$conn->bound_jid."; closed:".$conn->closed);
	return;
    }
    my $smid = $self->attr('{}previd');
    my $ctx = $plug->get_ctx($smid);
    unless($ctx) {
	$self->reply_error('item-not-found',
	    "Cannot find SM context for this connection: previd:".$self->attr('{}previd'));
	return;
    }
    my $h = DJabberd::Stanza::SMX::A::validate($self,$ctx);
    if($h<0) {
	$self->reply_error('unexpected-request',
	    "Cannot resume SM for this connection: handled seq.num is off the window ".$ctx->{last}." >>> ".$ctx->{tx});
	return;
    }
    my $old = $plug->get_conn($smid);
    unless($old->{closed} && $old->bound_jid && $old->vhost == $conn->vhost) {
	$self->reply_error('unexpected-request',
	    "Cannot resume SM for this connection: orignal connection ".$old->{id}." is still alive or unbound");
	return;
    }
    # we're positive about resumption now, just do it
    $plug->del_conn($smid);
    my $jid = $old->bound_jid;
    my $cb = DJabberd::Callback->new({
	registered => sub {
	    $conn->set_bound_jid($_[1]);
	},
	error => sub {
	    $plug->cleanup($smid);
	    $ctx = undef;
	}
    });
    # need to do this quickly to avoid losing writes... oh wait, we're single-threaded.
    $old->vhost->unregister_jid($jid,$old);
    # Steal JID binding - This is your last chance.
    $conn->vhost->register_jid($jid,$jid->resource,$conn,$cb);
    unless($ctx) {
	$self->reply_error('unexpected-request',
	    "Cannot resume SM for this connection: JID rebind failed for ".$jid->as_string);
	return;
    }
    $plug->add_conn($smid,$conn);
    # Copy connection state - After this there is no turning back.
    $conn->{iqctr} = $old->{iqctr};
    if($old->isa('DJabberd::Connection::ClientIn')) {
	$conn->set_available($old->is_available);
	$conn->set_requested_roster($old->requested_roster);
	$conn->{got_initial_presence} = $old->{got_initial_presence};
	$conn->{directed_presence} = $old->{directed_presence};
	$conn->{pend_in_subscriptions} = $old->{pend_in_subscriptions};
    }
    $self->SUPER::process($plug,$conn,$ctx,$smid);
    # now kick off queue processing - reset {last} to what the peer {h}andled
    $ctx->{last} = $h;
    $ctx->{win} = $ctx->{tx} - $h; # open wide to flush them all
    # and see how deep the rabbit hole goes.
    DJabberd::Stanza::SMX::A::process($self,$plug,$conn,$ctx,$h);
}

package DJabberd::Stanza::SMX::R;
use base 'DJabberd::Stanza::SMX';

sub make_response {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = shift;
    my $resp = $self->SUPER::make_response;
    $resp->set_attr('{}h',($ctx->{rx}%(2**32)));
    return $resp;
}
sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $smid = shift;
    my $ctx = $plug->get_ctx($conn->{in_stream});
    return unless($ctx);
    my $resp = $self->make_response($plug,$conn,$ctx);
    $resp->deliver($conn);
}

package DJabberd::Stanza::SMX::A;
use base 'DJabberd::Stanza::SMX';

sub validate {
    my $self = shift;
    my $ctx = shift;
    my $h = $self->attr('{}h');
    # TODO check uint32 wraping
    return $h if(defined $h && $ctx->{ack} <= $h && $h <= $ctx->{last});
    return -1;
}
sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = shift;
    my $h = shift;
    unless($ctx && ref($ctx) eq 'HASH') {
	$ctx = $plug->get_ctx($conn->{in_stream});
	unless($ctx && ref($ctx) eq 'HASH') {
	    $logger->error('Got ack with no context: '.$conn->{in_stream});
	    return;
	}
	$h = $self->validate($ctx);
	# we MAY error-close the stream, so let just do it as it may corrupt the queue and
	# basically means we're not in sync with the other side anyway
	$logger->logcroak("Invalid SM ACK: $h </> for ".$ctx->{ack}." last ".$ctx->{last}) if($h<0);
    }
    # ack stepped up, decrease nack pressure
    $ctx->{nack}-- if($ctx->{nack}>0 && $h > $ctx->{ack});
    # discard acked events from the queue
    while($ctx->{ack} < $h) {
	$ctx->{ack}++;
	shift(@{$ctx->{queue}});
    }
    $logger->debug("Advancing queue to $h, ".scalar(@{$ctx->{queue}})." items remain[".$ctx->{ack}.':'.$ctx->{last}.':'.$ctx->{tx}.']');
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
	my $xml = "<r xmlns='".$ctx->{ns}."'/>";
	$conn->log_outgoing_data($xml);
	$conn->write($xml) or $conn->write(undef);
	$logger->debug("Flushed $h items from the queue, waiting for ack...");
	$ctx->{win} = 1 if($ctx->{win} > $plug->max_win); # reset window
    }
}

=head1 FLOW CONTROL

There's internal option called paranoid and context option called flowcontrol
intended to complement [XEP-0198 v1.1 6] (sm:2) throttling requirements.

It was added as experimental flow control option which dimed useless in current
circumstances. Danga::Socket is not truly asynchronous event processing wrapper
as python twisted - where event loop runs in own helper thread, separately from
main loop thread.

This, together with synchronous nature of TCP creates a mess when dealing with
truly asynchronous clients. They are emitting stanzas in arbitrary order,
while all of them are processed sequentually by Danga::Socket loop, picking
data from tcp queue. SMX is then halting egress stream agressively requesting
for acknowledgement of last emitted stanza, but client will see it only after
Danga::Socket walked through entire TCP backlog, which would already contain
all previously emitted request/answer stanzas.

In short - don't use it. Unless you intend to experiment with UDP transport or
perl threads (eg. non-sequentual transport or truly async events). TCP flow
control is already good enough so SM is intended to detect tcp teardown
(informative ack), not replace flow control (delivery ack).

=cut
=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
