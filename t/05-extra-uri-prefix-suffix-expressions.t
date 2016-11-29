#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


my %uris = (
	'http://www1.rapidsoftclearon.net/' =>  { map { $_ => 1 } qw(
		www1.rapidsoftclearon.net/
		rapidsoftclearon.net/
	)},
);


my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $uri (keys(%uris)) {
	my @expressions = $gsb->canonical($uri);
	is(scalar(@expressions), scalar(keys(%{$uris{$uri}})), "Number of possible prefix/suffix expressions for '". $uri ."'");
	foreach my $expression (@expressions) {
		ok(exists($uris{$uri}->{$expression}), "prefix/suffix expression '". $expression ."' found");
		delete($uris{$uri}->{$expression});
	}
	is(scalar(keys(%{$uris{$uri}})), 0, "All prefix/suffix expressions found");
}
