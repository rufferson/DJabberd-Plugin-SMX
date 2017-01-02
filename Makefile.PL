#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Plugin::SMX',
	VERSION_FROM => 'lib/DJabberd/Plugin/SMX.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Plugin/SMX.pm',
	PREREQ_PM => {
		'DJabberd' => '0.86',
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
