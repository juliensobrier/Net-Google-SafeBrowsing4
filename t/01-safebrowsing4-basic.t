#!/usr/bin/perl

use strict;
use warnings;

use Test::More qw(no_plan);

BEGIN {
	use_ok('Net::Google::SafeBrowsing4');
};

require_ok('Net::Google::SafeBrowsing4');

my $gsb = new_ok('Net::Google::SafeBrowsing4' => [], 'Net::Google::SafeBrowsing4');


is( $gsb->hex_to_ascii( 'A' ), 41, 'hex_to_ascii OK');
is( $gsb->hex_to_ascii( $gsb->ascii_to_hex('11223344') ), '11223344', 'hex_to_ascii OK');
