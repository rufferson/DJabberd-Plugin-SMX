package DJabberd::Plugin::SMX;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';
use MIME::Base64;

# Deps
use DJabberd::Delivery::OfflineStorage;

use constant {
	NSv2 => "urn:xmpp:sm:2",
	NSv3 => "urn:xmpp:sm:3",
	NSCS => "urn:xmpp:csi:0",
	NSGQ => "google:queue",
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
	    resume <timeout_secs>
	    location <reconnect_addr:port>
	    csi <soft|hard>
	</Plugin>
    </VHost>

C<resume> here enables connection resumption with specified dead timeout, which
is 0 hence disabled by default;

C<location> sepcifies direct ip:port where session should be restored.
Use to avoid DNS loadbalancing in clustered environment.

C<csi> enables Client State Indication support which is also off by default.
Soft param just enables filtering while hard option totally stops egress
traffic, queueing it up in SM resumption buffer. Filtering and queuing is
activated only on reception of the <inactve/> nonza. On <active/> or resumption
the queue is flushed and filters are lifted.

B<Important:> it is required that client supports SM to have CSI working. Mere CSI
support won't work since context reference is stored as SM ID. CSI nonzas are
ignored without SM context.

For debugging purposes - for clients which support SM but not CSI (i.e. gajim)
option C<smcsi> will enable counting CSI nonzas in SM C<h> counter. Otherwise
after manually injecting CSI nonza following C<a> aborts the stream.

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
sub set_config_smcsi {
    my $self = shift;
    $self->{smcsi} = shift || 0;
}

sub finalize {
    my $self = shift;
    $self->{csi} ||= 0;
    $self->{resume} ||= 0;
    $self->{location} ||= '';
    $self->{smcsi} ||= 0;
}

=head2 register($self, $vhost)

Register the vhost with the module.

=cut

my %cls = (
    '{'.NSv2.'}r' => 'R',
    '{'.NSv3.'}r' => 'R',
    '{'.NSv2.'}a' => 'A',
    '{'.NSv3.'}a' => 'A',
    '{'.NSv2.'}enable' => 'Enable',
    '{'.NSv3.'}enable' => 'Enable',
    '{'.NSv2.'}resume' => 'Resume',
    '{'.NSv3.'}resume' => 'Resume',
    '{'.NSCS.'}active'   => 'CSA',
    '{'.NSCS.'}inactive' => 'CSI',
);
my %gq2cs = (
    '{'.NSGQ.'}enable'  => 'DJabberd::Stanza::SMX::CSI',
    '{'.NSGQ.'}disable' => 'DJabberd::Stanza::SMX::CSA',
);
sub register {
    my ($self,$vhost) = @_;
    my $stanza_cb = sub {
	my ($vh, $cb, $xe, $c) = @_;
	return $self unless($vh);
	if(my $cl = $cls{$xe->element}) {
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
	    $ctx->{rx}++ if($ctx && ref($ctx));
	    $ctx->{ts} = time;
	}
	$cb->decline;
    };
    my $filter_cb = sub {
	my ($vh, $cb, $get) = @_;
	my $stz = $get->();
	return $cb->decline if($stz->connection->is_server);
	my $ctx = $self->get_ctx($stz->connection->{in_stream}) || $self->get_ctx($stz->connection->bound_jid->as_string);
	return $cb->decline unless($ctx && ref($ctx));
	return $cb->decline if($ctx->{state} eq 'active');
	if($self->filter_stanza($stz,$ctx)) {
	    $cb->stop_chain;
	} else {
	    $self->flush($stz->connection);
	    $cb->decline;
	}
    };
    my $closure_cb = sub {
	my ($vh, $cb, $c) = @_;
	$logger->debug('Callback for stream '.$c->stream_id.' ['.$c->{id}.'] '.$c->{in_stream}.' for '.($c->bound_jid||'<null>'));
	return $cb->stop_chain if($c->{in_stream} && $self->{resume} && $self->stash_conn($c));
	# garbage collect - recreate smid, delete con/ctx - requires stream_id and bound_jid
	$self->gc_conn($c);
	$cb->decline;
    };
    my $c2s_iq_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->signature eq 'set-{'.NSGQ.'}query') {
	    # This is Google's CSI equivalent.
	    $logger->debug("Queueing: ".$iq->as_xml);
	    my $ctx = $self->get_ctx($iq->connection);
	    foreach($iq->first_element->children_elements) {
		$gq2cs{$_->element}->process($self,$iq->connection,$ctx)
		    if(exists $gq2cs{$_->element});
	    }
	    $self->flush($iq->connection,$ctx);
	    $iq->send_result;
	    return $cb->stop_chain;
	}
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    Scalar::Util::weaken($self->{vhost});
    $vhost->register_hook("HandleStanza",$stanza_cb);
    $vhost->register_hook("filter_incoming_client",$handler_cb);
    $vhost->register_hook("pre_stanza_write",$filter_cb);
    $vhost->register_hook("ConnectionClosing",$closure_cb);
    $vhost->register_hook('SendFeatures',sub {
        my ($vh, $cb, $conn) = @_;
        return $cb->stanza("<sm xmlns='".NSv2."'/><sm xmlns='".NSv3."'/>".($self->{csi} ? "<csi xmlns='".NSCS."'/>" : ''))
	    if($conn->sasl && $conn->sasl->authenticated_jid);
	$cb->decline;
    });
    $vhost->register_hook("c2s-iq",$c2s_iq_cb);
    $vhost->caps->add(DJabberd::Caps::Feature->new(NSGQ));
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
    return 0 unless($ctx && ref($ctx) && $ctx->{resume});
    # release resources and remove from event loop
    DJabberd::Connection::close($conn); # damn I hate these types of calls but there's no other way
    $ctx->stop_hb;
    # but now allow connection to be used for delivery
    $conn->{closed} = -1;
    # Setup resume timeout handler
    $logger->debug("Will expire connection ".$conn->{id}." in ".$ctx->{resume}." seconds");
    $ctx->{timeout} = Danga::Socket->AddTimer($ctx->{resume},sub {
	$conn->log->info("Delayed session timed out unresumed: ".$conn->bound_jid->as_string."/".$conn->{in_stream});
	# Unregister and call cleanup to remove con/ctx
	$conn->{closed} = 0;
	$conn->unbind;
	$self->cleanup($conn->{in_stream});
	$conn->{closed} = 1;
	$conn->{in_stream} = 1;
	# run hook_chain which we've intercepted again
	$conn->close;
    });
    Scalar::Util::weaken($ctx->{timeout});
    return 1;
}

sub gc_conn {
    my $self = shift;
    my $conn = shift;
    return unless($conn->bound_jid && $conn->stream_id);
    my $smid = $conn->{in_stream};
    $smid = $self->conn_id($conn) unless($smid && $self->{cons}->{$smid} && $self->{cons}->{$smid} == $conn);
    my ($con,$ctx) = $self->cleanup($smid);
    $ctx = delete $self->{ctxs}->{$conn->bound_jid->as_string} unless($ctx && ref($ctx));
    if($ctx && ref($ctx)) {
	$ctx->stop_hb;
    } else {
	$logger->error("Cannot cleanup resources for connection ".$conn->{id}." with smid $smid/".$conn->bound_jid->as_string);
    }
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
    return @ret;
}

sub get_ctx {
    my $self = shift;
    my $smid = shift;
    return $self->{ctxs}->{$smid}
	unless(ref($smid));
    return $self->{ctxs}->{$smid->{in_stream}}
	if($smid->{in_stream} && exists $self->{ctxs}->{$smid->{in_stream}});
    return $self->{ctxs}->{$smid->bound_jid->as_string}
	if(!$smid->is_server && exists $self->{ctxs}->{$smid->bound_jid->as_string});
    return undef if($smid->is_server);
    return $self->{ctxs}->{$smid->bound_jid->as_string} = DJabberd::Plugin::SMX::Ctx->new;
}

sub filter_stanza {
    my $slef = shift;
    my $stz = shift;
    my $ctx = shift;
    if($stz->element_name eq 'message') {
	# pass the message with body on - if it's normal chat
	my $type = $stz->attr('{}type') || 'normal';
	if($type eq 'chat' or $type eq 'normal') {
	    return 0 if(grep {$_->element_name eq 'body'} $stz->children_elements);
	}
    } elsif($stz->element_name eq 'iq') {
	# we can hardly filter iq, it's interactive
	return 0;
    } else {
	# well, presence, it can be chatty so we may need to queue
	if(!$stz->type || $stz->type eq 'unavailable') {
	    DJabberd::Delivery::OfflineStorage::add_delay($stz);
	    $ctx->{pq}->{$stz->from} = $stz;
	    return 1;
	}
	return 0;
    }
    # drop this one
    return 1;
}

sub flush {
    my $self = shift;
    my $conn = shift;
    my $ctx = shift || $self->get_ctx($conn);
    foreach(keys(%{$ctx->{pq}})) {
	my $stz = delete $ctx->{pq}->{$_};
	if($stz && ref($stz)) {
	    $conn->write_stanza($stz);
	}
    }
}

package DJabberd::Plugin::SMX::Ctx;

sub new {
    my $class = shift;
    my $self = bless {
	state => 'active',
	next => undef,
	pq => {},
	@_
    }, $class;
    return $self;
}

sub start_hb {
    my $self = shift;
    my $conn = shift;
    my $time = shift || 300;
    $self->stop_hb;
    $self->{next} = Danga::Socket->AddTimer($time,$self->do_hb($conn,$time));
    Scalar::Util::weaken($self->{next});
    $logger->debug("Started timer ".$self->{next}."[".$self->{next}->[0]."]");
}

sub stop_hb {
    my $self = shift;
    if(exists $self->{next} && ref($self->{next})) {
	my $tmr = delete $self->{next};
	$tmr->cancel;
	$logger->debug("Stopped timer $tmr\[".$tmr->[0]."]");
    }
}

sub do_hb {
    my $self = shift;
    my $conn = shift;
    my $time = shift;
    return sub {
        $conn->write(' ');
	#$conn->write(' ') or $conn->write(undef); # enforce if queued
	$logger->debug("Whitespace ping! at connection ".$conn->{id});
	$self->start_hb($conn,$time);
    };
}

package DJabberd::Plugin::SMX::Ctx::SM;
use base 'DJabberd::Plugin::SMX::Ctx';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(
	rx => 0, tx => 0,
	ack => 0, nack => 0,
	last => 0,
	win => 1,
	queue => [],
	@_
    );
    return $self;
}

sub r {
    my $self = shift;
    my $conn = shift;
    my $delta = shift || $self->{tx}-$self->{ack};
    $logger->debug("Requesting ack for (ack<delta<last<=tx\@win/nack) "
	    .$self->{ack}." < ".$delta." < ".$self->{last}." <= ".$self->{tx}
	    ." @ ".$self->{win}." / ".$self->{nack});
    my $xml = "<r xmlns='".$self->{ns}."'/>";
    $conn->log_outgoing_data($xml);
    #$conn->write($xml) or $conn->write(undef); # enforce if queued
    $conn->write($xml);
}

sub do_hb {
    my $self = shift;
    my $conn = shift;
    return sub {
	$logger->debug("SM ping! at connection ".$conn->{id});
	$self->r($conn);
    };
}

sub ack {
    my ($self,$ack) = @_;
    # ack stepped up, decrease nack pressure
    $self->{nack}-- if($self->{nack}>0 && $ack > $self->{ack});
    # discard acked events from the queue
    while($self->{ack} < $ack) {
	$self->{ack}++;
	shift(@{$self->{queue}});
    }
    $logger->debug("Advancing queue to $ack, ".scalar(@{$self->{queue}})
	    ." items remain[".$self->{ack}.':'.$self->{last}.':'.$self->{tx}.']');
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
	#$conn->write(undef);
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
	    "Cannot enable SM for this connection: streamOpen:".$conn->{in_stream}
	    ."; ID:".$conn->stream_id."; bound:".$conn->bound_jid->as_string."; closed:".$conn->closed);
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
    unless($ctx && ref($ctx)) {
	return unless($self->validate($plug,$conn,$conn_id));
	# Initialize brand new one unless it was passed to us
	$ctx = DJabberd::Plugin::SMX::Ctx::SM->new(ns => $self->attr('{}xmlns'));
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
	# window is never shut by SM, only from outside (eg. CSI)
	if(!$conn->{closed} && $ctx->{win} > 0) {
	    # discard next ack timer if it hasn't fired
	    $ctx->stop_hb;
	    my $d = $ctx->{tx} - $ctx->{ack};
	    # push data to the wire
	    $conn->write($$ref);
	    $ctx->{last} = $ctx->{tx};
	    # if window is full - request ack
	    if($d >= $ctx->{win}) {
		$ctx->r($conn,$d);
		# if it's more than full - try to narrow down the window
		$ctx->{win}-- if($ctx->{win}>1 && $ctx->{nack}>0);
		# and pump the nack pressure
		$ctx->{nack}++ if($d > $ctx->{win});
	    } elsif($ctx->{state} ne 'active') {
	    	# resumption will provide latest ack, but we may never mark conn as down while inactive
		$ctx->start_hb($conn);
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
	$self->reply_error('item-not-found',
	    "Cannot resume SM for this connection: handled seq.num is off the window ".$ctx->{last}." >>> ".$ctx->{tx});
	return;
    }
    my $old = $plug->get_conn($smid);
    unless($old->bound_jid && $old->vhost == $conn->vhost) {
	$self->reply_error('item-not-found',
	    "Cannot resume SM for this connection: orignal connection ".$old->{id}." is already unbound");
	return;
    }
    unless($old->{closed}) {
	if((time - $ctx->{ts}) < $ctx->{resume}/2) {
	    $self->reply_error('item-not-found',
		"Cannot resume SM for this connection: orignal connection ".$old->{id}." is still active");
	    return;
	} else {
	    # Terminate stream and close socket, straight and simple
	    my $txt="Request to resume session $smid, current connection is stale";
	    $old->write("
		<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>
		    <text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>
			$txt
		    </text>
		</stream:error>
	    </stream:stream>");
	    $old->log->warn($old->{id}." conflict: $txt");
	    DJabberd::Connection::close($old);
	}
    }
    # we're positive about resumption now, just do it
    $ctx->{timeout}->cancel if(exists $ctx->{timeout} && ref($ctx->{timeout}));
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
	$self->reply_error('item-not-found',
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
    my $old_win = $ctx->{win};
    $ctx->{win} = $ctx->{tx} - $ctx->{last};
    DJabberd::Stanza::SMX::A::process($self,$plug,$conn,$ctx,$h);
    $plug->flush($conn,$ctx) if($ctx->{state} ne 'active');
    $ctx->{win} = $old_win;
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
    unless($ctx && ref($ctx)) {
	$ctx = $plug->get_ctx($conn->{in_stream});
	unless($ctx && ref($ctx)) {
	    $logger->error('Got ack with no context: '.$conn->{in_stream});
	    return;
	}
	$h = $self->validate($ctx);
	# we MAY error-close the stream, so let just do it as it may corrupt the queue and
	# basically means we're not in sync with the other side anyway
	$logger->logcroak("Invalid SM ACK: $h </> for ".$ctx->{ack}." last ".$ctx->{last}) if($h<0);
	$ctx->{ts} = time;
    }
    $ctx->ack($h);
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
	$ctx->r($conn,$ceil);
	$logger->debug("Flushed $h items from the queue, waiting for ack...");
	$ctx->{win} = 1 if($ctx->{win} > $plug->max_win); # reset window
    }
    if($ctx->{nack} == 0 && $ctx->{state} ne 'active') {
	# no ack pressure, silenced connection - schedule heartbeat
	$ctx->start_hb($conn);
    }
}

package DJabberd::Stanza::SMX::CSA;
use base 'DJabberd::Stanza::SMX';

sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = shift;
    unless($ctx && ref($ctx)) {
	$ctx = $plug->get_ctx($conn);
	unless($ctx) {
	    $logger->debug("Cannot obtain connection context ".$conn->{stream_id}." ".$conn->{in_stream}." ".$conn->bound_jid);
	    return;
	}
	$ctx->{ts} = time;
	$ctx->{rx}++ if($plug->{smcsi});
	return if($ctx->{state} eq 'active');
    }
    $logger->debug("User indicated active state, resuming normal flow from ".$ctx->{state});
    if(exists $ctx->{win} && $ctx->{win} <= 0) {
	# open the window and flush the queue
	if($ctx->{tx}>$ctx->{last}) {
	    $ctx->{win} = $ctx->{tx} - $ctx->{last};
	    DJabberd::Stanza::SMX::A::process($self,$plug,$conn,$ctx,$ctx->{tx});
	} else {
	    $ctx->{win} = 1;
	}
    }
    # now flush accumulated presence
    $plug->flush($conn,$ctx);
    $ctx->stop_hb;
    # and lift the filters
    $ctx->{state} = 'active';
}

package DJabberd::Stanza::SMX::CSI;
use base 'DJabberd::Stanza::SMX';

sub process {
    my $self = shift;
    my $plug = shift;
    my $conn = shift;
    my $ctx = shift;
    unless($ctx && ref($ctx)) {
	$ctx = $plug->get_ctx($conn);
	unless($ctx) {
	    $logger->debug("Cannot obtain connection context ".$conn->{stream_id}." ".$conn->{in_stream}." ".$conn->bound_jid);
	    return;
	}
	$ctx->{rx}++ if($plug->{smcsi});
    }
    return if($ctx->{state} ne 'active' or !$plug->{csi});
    $ctx->{state} = 'inactive';
    $ctx->{win} = 0 if(exists $ctx->{win} && $ctx->{win} && $plug->{csi} eq 'hard' && ref($self));
    $logger->debug("User indicated inactive state, making ".$plug->{csi}." suspension");
    $ctx->start_hb($conn);
}

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
