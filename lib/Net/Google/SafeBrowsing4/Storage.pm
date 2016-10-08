package Net::Google::SafeBrowsing4::Storage;


use strict;
use warnings;

use Carp;


our $VERSION = '0.1';

=head1 NAME

Net::Google::SafeBrowsing4::Storage - Base class for storing the Google Safe Browsing v4 database

=head1 SYNOPSIS

  package Net::Google::SafeBrowsing4::File;

  use base 'Net::Google::SafeBrowsing4::Storage';

=head1 DESCRIPTION

This is the base class for implementing a storage mechanism for the Google Safe Browsing v4 database. See L<Net::Google::SafeBrowsing4::File> for an example of implementation.

This module cannot be used on its own as it does not actually store anything. All methods should redefined. Check the code to see which arguments are used, and what should be returned.

=cut


=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

  Create a Net::Google::SafeBrowsing4::Storage object

  my $storage	=> Net::Google::SafeBrowsing4::Storage->new();

=cut

sub new {
	my ($class, %args) = @_;

	my $self = {
		%args,
	};

	bless $self, $class or croak "Can't bless $class: $!";
    return $self;
}

=head1 PUBLIC FUNCTIONS

=over 4

=back

=head2 save()

Add chunk information to the local database

  $storage->save(add => [...], remove => [...], state => '...', list => { threatType => ..., threatEntryType => ..., platformType => ... });

Return the new list of local hashes.


Arguments

=over 4

=item override

Optional. override the local list of hashes. 0 by default (do not override)

=item hashes

Optional. List of hashes to add.

=item remove

Optional. List of hash indexes to remove.

=item state

Optional. New list state.

=item list

Required. Google Safe Browsing list.


=back

=cut


sub save {
	my ($self, %args) = @_;
	my $list 			= $args{list} 			|| croak "Missing list information";
	my $override	= $args{override}		|| 0;
	my @hashes		= @{ $args{add} 		|| [] };
	my @remove		= @{ $args{remove} 	|| [] };
	my $state			= $args{'state'}		|| '';
	
	# save the information somewhere
	
	# return the list of hashes, sorted, from the new storage
	return @hashes;
}


=head2 reset()

Remove all local data.

	$storage->reset(list => { threatType => ..., threatEntryType => ..., platformType => ... });


Arguments

=over 4

=item list

Required. Google Safe Browsing list.

=back

No return value

=cut

sub reset {
	my ($self, %args) = @_;
	my $list 			= $args{list} 			|| croak "Missing list information\n";
	
	# remove all hashes, empty state
}


=head2 next_update()

Ge the timestamp when the local database update is allowed.

	my $next = $storage->next_update();


No arguments

=cut

sub next_update {
	my ($self, %args) = @_;

	# retrieve information from storage
	
	return time() - 10;
}


=head2 get_state()

Return the current state of the list.

	my $state = $storage->get_state(list => { threatType => ..., threatEntryType => ..., platformType => ... });


Arguments

=over 4

=item list

Required. Google Safe Browsing list.

=back


=cut

sub get_state {
	my ($self, %args) = @_;
	my $list 			= $args{list} 			|| croak "Missing list information\n";
		
	return "";
}



=head2 get_prefixes()

Return the list of prefxies that match a full hash for a given list.

	my @prefixes = $storage->get_prefixes(hashes => [...], list => { threatType => ..., threatEntryType => ..., platformType => ... });


Arguments

=over 4

=item list

Required. Google Safe Browsing list.

=back

=item hashes

Required. List of full hashes.

=back


=cut

sub get_prefixes {
	my ($self, %args) = @_;
	my $list 			= $args{list} 			|| croak "Missing list information\n";
	my @hashes		= @{ $args{hashes} 	|| [] };

  return ({ prefix => '...', list => $list });
}

=head2 updated()

Save information about a successful database update

	$storage->updated('time' => time(), next => time() + 1800);


Arguments

=over 4

=item time

Required. Time of the update.

=item next

Required. Time of the next update allowed.

=back


No return value

=cut

sub updated {
	my ($self, %args) = @_;
	my $time = $args{'time'}	|| time();
	my $next = $args{'next'}	|| time() + 1800;
	
	# next update applies to all lists, save it
}



=head2 get_full_hashes()

Return a list of full hashes

	$storage->get_full_hashes(hash => AAAAAAAA..., lists => [{ threatType => '...', threatEntryType => '...', platformType => '...' }]);


Arguments

=over 4

=item hash

Required. 32-bit hash


=item lists

Required. Google Safe Browsing lists

=back

Return value

=over 4

Array of full hashes:

    ({ hash => HEX, type => 0 }, { hash => HEX, type => 1 }, { hash => HEX, type => 0 })

=back


=cut

sub get_full_hashes {
	my ($self, %args) = @_;
	my @lists 				= @{ $args{lists} || [] };
	my $hash					= $args{hash}			|| return ();

	return (
		{ hash => $self->ascii_to_hex('eb9744c011d332ad9c92442d18d5a0f913328ad5623983822fc86fad1aab649d'), list => { threatType => '...', threatEntryType => '...', platformType => '...' }, expire => time() + 300 },
		{ hash => $self->ascii_to_hex('2ae11a967a5517e24c7be3fa0b8f56e7a13358ce3b07556dc251bc6b650f0f59'), list => { threatType => '...', threatEntryType => '...', platformType => '...' }, expire => time() + 300 }
	);
}



=head2 update_error()

Save information about a failed database update

	$storage->update_error('time' => time(), wait => 60, errors => 1);


Arguments

=over 4

=item time

Required. Time of the update.

=item wait

Required. Number of seconds to wait before doing the next update.

=item errors

Required. Number of errors.

=back


No return value

=cut

sub update_error {
	my ($self, %args) 	= @_;
	my $time			= $args{'time'}	|| time();
	my $list			= $args{'list'}	|| '';
	my $wait			= $args{'wait'}	|| 60;
	my $errors		= $args{errors}	|| 1;

	# UPDATE updates SET last = $time, wait = $wait, errors = $errors, list = $list
}

=head2 last_update()

Return information about the last database update

	my $info = $storage->last_update();


No arguments


Return value

=over 4

Hash reference

	{
		time	=> time(),
		errors	=> 0
	}

=back

=cut

sub last_update {
	my ($self, %args) 	= @_;

	return {'time' => time(), errors => 0};
}

=head2 add_full_hashes()

Add full hashes to the local database

	$storage->add_full_hashes(timestamp => time(), full_hashes => [{hash => HEX, list => { }, cache => "300s"}]);


Arguments

=over 4

=item timestamp

Required. Time when the full hash was retrieved.

=item full_hashes

Required. Array of full hashes. Each element is an hash reference in the following format:

	{
		hash		=> HEX,
		list		=> { }',
		cache => "300s"
	}

=back


No return value


=cut

sub add_full_hashes {
	my ($self, %args) 	= @_;
	my $timestamp				= $args{timestamp}		|| time();
	my $full_hashes			= $args{full_hashes}	|| [];

	foreach my $hash (@$full_hashes) {
		# INSERT INTO [...] (hash, list, timestamp, end,type ) VALUES ($hash->{chunknum}, $hash->{hash}, $hash->{list}, $timestamp, $timestamp + $hash->{life}, $hash->{type});
	}
}

=head2 full_hash_error()

Save information about failed attempt to retrieve a full hash

	$storage->full_hash_error(timestamp => time(), prefix => HEX);


Arguments

=over 4

=item timestamp

Required. Time when the Google returned an error.

=item prefix

Required. Host prefix.

=back


No return value


=cut

sub full_hash_error {
	my ($self, %args) 	= @_;
	my $timestamp		= $args{timestamp}	|| time();
	my $prefix			= $args{prefix}			|| '';

	# Add 1 to existing error count
}

=head2 full_hash_ok()

Save information about a successful attempt to retrieve a full hash

	$storage->full_hash_ok(timestamp => time(), prefix => HEX);


Arguments

=over 4

=item timestamp

Required. Time when the Google returned an error.

=item prefix

Required. Host prefix.

=back


No return value


=cut

sub full_hash_ok {
	my ($self, %args) 	= @_;
	my $timestamp		= $args{timestamp}	|| time();
	my $prefix			= $args{prefix}		|| '';

	# UPDATE full_hashes_errors SET errors = 0, timestamp = $timestamp WHERE prefix = $prefix
}

=head2 get_full_hash_error()

Save information about an unsuccessful attempt to retrieve a full hash

	my $info = $storage->get_full_hash_error(prefix => HEX);


Arguments

=over 4

=item prefix

Required. Host prefix.

=back


Return value

=over 4

undef if there was no error

Hash reference in the following format if there was an error:

	{
		timestamp 	=> time(),
		errors		=> 3
	}

=back


=cut

sub get_full_hash_error {
	my ($self, %args) 	= @_;
	my $prefix			= $args{prefix}		|| '';


	# no error
	return undef;

	# some error
	# return { timestamp => time(), errors => 3 }
}




=head1 PRIVATE FUNCTIONS

These functions are not intended for debugging purpose.

=over 4

=back

=head2 hex_to_ascii()

Transform hexadecimal strings to printable ASCII strings. Used mainly for debugging.

  print $storage->hex_to_ascii('hex value');

=cut

sub hex_to_ascii {
	my ($self, $hex) = @_;


	my $ascii = '';

	while (length $hex > 0) {
		$ascii .= sprintf("%02x",  ord( substr($hex, 0, 1, '') ) );
	}

	return $ascii;
}

=head2 ascii_to_hex()

Transform ASCII strings to hexadecimal strings.

	  print $storage->ascii_to_hex('ascii value');

=cut

sub ascii_to_hex {
	my ($self, $ascii) = @_;

	my $hex = '';
	for (my $i = 0; $i < int(length($ascii) / 2); $i++) {
		$hex .= chr hex( substr($ascii, $i * 2, 2) );
	}

	return $hex;
}


=head2 debug()

Print debug output.

=cut

sub debug {
	my ($self, @messages) = @_;

	print join('', @messages, "\n") if ($self->{debug} > 0);
}


=head2 error()

Print error message.

=cut

sub error {
	my ($self, $message) = @_;

	print "ERROR - ", $message if ($self->{debug} > 0 || $self->{errors} > 0);
	$self->{last_error} = $message;
}

=head1 CHANGELOG

=over 4


=item 0.1

Initial release.

=back

=head1 SEE ALSO

See L<Net::Google::SafeBrowsing4> for handling Google Safe Browsing v4.

See L<Net::Google::SafeBrowsing4::File> for an example of storing and managing the Google Safe Browsing database.

Google Safe Browsing v4 API: L<https://developers.google.com/safe-browsing/v4/>

=head1 AUTHOR

Julien Sobrier, E<lt>julien@sobrier.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 by Julien Sobrier

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;
