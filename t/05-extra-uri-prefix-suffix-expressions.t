#!/usr/bin/perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4::URI;


my %uris = (
	'http://www1.rapidsoftclearon.net/' =>  { map { $_ => 1 } qw(
		www1.rapidsoftclearon.net/
		rapidsoftclearon.net/
	)},
	'www.google.com' =>  { map { $_ => 1 } qw(
		www.google.com/
		google.com/
	)},
	'google.com' =>  { map { $_ => 1 } qw(
		google.com/
	)},
	'malware.testing.google.test' =>  { map { $_ => 1 } qw(
		malware.testing.google.test/
		testing.google.test/
		google.test/
	)},
);

foreach my $uri (keys(%uris)) {
	note("Checking uri: " . $uri . "\n");
	my $gsb_uri = Net::Google::SafeBrowsing4::URI->new($uri);
	my @lookups = $gsb_uri->generate_lookupuris();
	is(scalar(@lookups), scalar(keys(%{$uris{$uri}})), "Number of possible prefix/suffix uris for '". $uri ."'");
	foreach my $lookupuri (@lookups) {
		my $expression = $lookupuri->as_string();
		$expression =~ s/^https?:\/\///i;
		ok(exists($uris{$uri}->{$expression}), "prefix/suffix uri '". $expression ."' found");
		delete($uris{$uri}->{$expression});
	}
	is(scalar(keys(%{$uris{$uri}})), 0, "All prefix/suffix uris found");
}
