#!/usr/bin/perl
use strict;
use Test::More tests => 8;
use_ok("DJabberd::Plugin::SMX");
ok(DJabberd::Stanza::SMX->new,"Stanza::SMX");
ok(DJabberd::Stanza::SMX::Enable->new,"Stanza::SMX::Enable");
ok(DJabberd::Stanza::SMX::Resume->new,"Stanza::SMX::Resume");
ok(DJabberd::Stanza::SMX::A->new,"Stanza::SMX::A");
ok(DJabberd::Stanza::SMX::R->new,"Stanza::SMX::R");
ok(DJabberd::Stanza::SMX::R->new,"Stanza::SMX::CSI");
ok(DJabberd::Stanza::SMX::R->new,"Stanza::SMX::CSA");
