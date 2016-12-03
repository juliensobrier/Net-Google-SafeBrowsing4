#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


my %uris = (
	'foo...com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'FoO..com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'foo.com...' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'...foo.com' =>  { map { $_ => 1 } qw(
		foo.com
	)},
	'www.google.com' =>  { map { $_ => 1 } qw(
		www.google.com
		google.com
	)},
	'google.com' =>  { map { $_ => 1 } qw(
		google.com
	)},
	'malware.testing.google.test' =>  { map { $_ => 1 } qw(
		malware.testing.google.test
		testing.google.test
		google.test
	)}
);


my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $uri (keys(%uris)) {
	my @expressions = $gsb->canonical_domain($uri);
	is(scalar(@expressions), scalar(keys(%{$uris{$uri}})), "Number of possible prefix/suffix expressions for '". $uri ."'");
	foreach my $expression (@expressions) {
		ok(exists($uris{$uri}->{$expression}), "prefix/suffix expression '". $expression ."' found");
		delete($uris{$uri}->{$expression});
	}
	is(scalar(keys(%{$uris{$uri}})), 0, "All prefix/suffix expressions found");
}
