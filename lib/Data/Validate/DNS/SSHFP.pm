# COPYRIGHT

package Data::Validate::DNS::SSHFP;

# ABSTRACT: Validate DNS SSH Fingerprint (SSHFP) Record Values

use 5.010;
use strict;
use warnings;

use parent 'Exporter';

use Taint::Util 'untaint';

our @EXPORT_OK = qw(
    is_sshfp_algorithm
    is_sshfp_fptype
    is_sshfp_fingerprint);

our %EXPORT_TAGS = (all => \@EXPORT_OK);

my %DIGESTS = (
    1 => 'SHA-1',
    2 => 'SHA-256');

=method new()

Constructor

=cut

sub new {
    my $class = shift;
    bless {}, ref $class || $class;
}

=func is_sshfp_algorithm($value, %options)

Returns the untainted algorithm number if it is a valid SSHFP algorithm number.

Options:

=for :list
* B<strict> [default: true]
Require that the algorithm is one of the registered values in the L<IANA Registry|https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml>

=cut

sub is_sshfp_algorithm {
    my ($self, $value, %opts) = _maybe_oo(@_);

    return unless defined $value;

    $opts{strict} //= 1;

    if ($value =~ /[^0-9]/) {
        return
    }

    # see https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml
    if ($opts{strict}) {
        if ($value < 1 or $value > 4) {
            return;
        }
    }

    untaint($value);

    return $value;
}

=func is_sshfp_fptype($value, %options)

Return the untainted fingerprint type number if it is a valid SSHFP fingerprint number.

Options:

=for :list
* B<strict> [default: true]
Require that the value is one of the registered values in the L<IANA Registry|https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml>

=cut

sub is_sshfp_fptype {
    my ($self, $value, %opts) = _maybe_oo(@_);

    return unless defined $value;

    $opts{strict} //= 1;

    if ($value =~ /[^0-9]/) {
        return
    }

    # see https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml
    if ($opts{strict}) {
        if ($value < 1 or $value > 2) {
            return;
        }
    }

    untaint($value);

    return $value;
}

=func is_sshfp_fingerprint($fptype, $value, %options)

Return the untainted value if it looks like a valid SSHFP fingerprint string
for the given fingerprint type.

Options:

=for :list
* B<strict> [default: true]
Require that C<$fptype> is one of the registered values in the L<IANA Registry|https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml>

=cut

sub is_sshfp_fingerprint {
    my ($self, $fptype, $value, %opts) = _maybe_oo(@_);

    $opts{strict} //= 1;

    return unless defined $value and is_sshfp_fptype($fptype, %opts);

    # extract only hex chars
    (my $data = $value) =~ s/[^0-9a-fA-F]//g;

    my %digest_length = (
        1 => 40,
        2 => 64);

    if (length $data != $digest_length{$fptype}) {
        return;
    }

    untaint($value);

    return $value;
}

sub _maybe_oo {
    my $self = shift if ref $_[0];

    return ($self, @_);
}

1;

__END__

=head1 SYNOPSIS

 use Data::Validate::DNS::SSHFP ':all';

 if (is_sshfp_algorithm(3)) {
     print 'Looks like a valid SSHFP algorithm';
 }

 if (is_sshfp_fptype(2)) {
    print 'Looks like a valid SSHFP fingerprint type';
 }

 if (is_sshfp_finterprint($fptype, $fingerprint)) {
    print 'Looks like a valid SSHFP Fingerprint';
 }

 # Or, use object syntax:
 my $v = Data::Validate::DNS::SSHFP->new;

 if ($v->is_sshfp_fptype($value)) {
    ...
 }

 # etc.

=head1 DESCRIPTION

This module offers functions for validating DNS SSH Fingerprint (SSHFP) record
fields to make input validation and untainting easier and more readable.

All of the functions return an untainted value on success and a false value
(undef or empty list) on failure.  In scalar context you should check that the
return value is defined.

All functions can be called as methods if using the object oriented interface.

=head1 SEE ALSO

=for :list
* L<RFC 4255|https://tools.ietf.org/html/rfc4255>
* L<IANA Registry for SSHFP RR Parameters|https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml>

