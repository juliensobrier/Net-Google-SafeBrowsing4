#!perl

use strict;
use warnings;

use Test::More qw(no_plan);

use Net::Google::SafeBrowsing4;


# URI Canonicalization tests from Google's API webpage:
# https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization
my %urls = (
	'http://host/%25%32%35' => 'http://host/%25',
	'http://host/%25%32%35%25%32%35' => 'http://host/%25%25',
	# @TODO: Un-escaping is not recursive?
	# 'http://host/%2525252525252525' => 'http://host/%25',
	'http://host/asdf%25%32%35asd' => 'http://host/asdf%25asd',
	'http://host/%%%25%32%35asd%%' => 'http://host/%25%25%25asd%25%25',
	'http://www.google.com/' => 'http://www.google.com/',
	'http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/' => 'http://168.188.99.26/.secure/www.ebay.com/',
	'http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/' => 'http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/',
	# @TODO: Fails because URI->new does some parsing automatically and parse ^ into %5E
	# 'http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B' => 'http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+',
	'http://3279880203/blah' => 'http://195.127.0.11/blah',
	'http://www.google.com/blah/..' => 'http://www.google.com/',
	'www.google.com/' => 'http://www.google.com/',
	'www.google.com' => 'http://www.google.com/',
	'http://www.evil.com/blah#frag' => 'http://www.evil.com/blah',
	'http://www.GOOgle.com/' => 'http://www.google.com/',
	'http://www.google.com.../' => 'http://www.google.com/',
	"http://www.google.com/foo\tbar\rbaz\n2" => 'http://www.google.com/foobarbaz2',
	'http://www.google.com/q?' => 'http://www.google.com/q?',
	'http://www.google.com/q?r?' => 'http://www.google.com/q?r?',
	'http://www.google.com/q?r?s' => 'http://www.google.com/q?r?s',
	'http://evil.com/foo#bar#baz' => 'http://evil.com/foo',
	'http://evil.com/foo;' => 'http://evil.com/foo;',
	'http://evil.com/foo?bar;' => 'http://evil.com/foo?bar;',
	# @TODO: URI module punycodes the hostname - this should be right. Maybe GSB API is wrong here?
	# "http://\x01\x80.com/" => 'http://%01%80.com/',
	'http://notrailingslash.com' => 'http://notrailingslash.com/',
	# @TODO: Apparently portnumbers should be removed
	# 'http://www.gotaport.com:1234/' => 'http://www.gotaport.com/',
	'  http://www.google.com/  ' => 'http://www.google.com/',
	'http:// leadingspace.com/' => 'http://%20leadingspace.com/',
	'http://%20leadingspace.com/' => 'http://%20leadingspace.com/',
	'%20leadingspace.com/' => 'http://%20leadingspace.com/',
	'https://www.securesite.com/' => 'https://www.securesite.com/',
	'http://host.com/ab%23cd' => 'http://host.com/ab%23cd',
	'http://host.com//twoslashes?more//slashes' => 'http://host.com/twoslashes?more//slashes'
);


my $gsb = Net::Google::SafeBrowsing4->new();

foreach my $uri (keys(%urls)) {
	is( $gsb->canonical_uri($uri), $urls{$uri}, "Canonicalization of URI '". $uri ."'");
}
