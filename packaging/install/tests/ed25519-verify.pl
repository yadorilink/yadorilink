# Test-only stand-in for the pinned verifier binary: RFC 8032 reference Ed25519
# verification in perl. The fixture release serves a wrapper around this file.
use strict;
use warnings;
use Math::BigInt;
use Digest::SHA qw(sha512);

# RFC 8032 section 6 reference algorithm: Ed25519 verification only.
# usage: perl verifier PUBKEY_HEX MESSAGE_FILE SIGNATURE_FILE ; exit 0 = valid
my ($pubhex, $msgf, $sigf) = @ARGV;
sub slurp { open(my $f, '<:raw', $_[0]) or exit 2; local $/; my $d = <$f>; close $f; return $d; }
sub bn { return Math::BigInt->new($_[0]); }
sub bdivs { return scalar($_[0]->copy->bdiv($_[1])); }
sub leint { return bn('0x' . unpack('H*', scalar reverse $_[0])); }

my $P = bn(2)->bpow(255)->bsub(19);
my $L = bn(2)->bpow(252)->badd(bn('27742317777372353535851937790883648493'));
sub inv { return $_[0]->copy->bmodpow($P - 2, $P); }
my $D = (($P - 121665) * inv(bn(121666))) % $P;
my $I = bn(2)->bmodpow(bdivs($P - 1, 4), $P);

sub padd {
    my ($p, $q) = @_;
    my $a = (($p->[1] - $p->[0]) * ($q->[1] - $q->[0])) % $P;
    my $b = (($p->[1] + $p->[0]) * ($q->[1] + $q->[0])) % $P;
    my $c = ($p->[3] * 2 * $D * $q->[3]) % $P;
    my $d = ($p->[2] * 2 * $q->[2]) % $P;
    my ($e, $f, $g, $h) = ($b - $a, $d - $c, $d + $c, $b + $a);
    return [($e * $f) % $P, ($g * $h) % $P, ($f * $g) % $P, ($e * $h) % $P];
}
sub pmul {
    my ($s, $p) = @_;
    my $q = [bn(0), bn(1), bn(1), bn(0)];
    my @bits = split //, ($s->as_bin =~ s/^0b//r);
    for my $bit (@bits) {
        $q = padd($q, $q);
        $q = padd($q, $p) if $bit eq '1';
    }
    return $q;
}
sub peq {
    my ($p, $q) = @_;
    return 0 if (($p->[0] * $q->[2] - $q->[0] * $p->[2]) % $P) != 0;
    return 0 if (($p->[1] * $q->[2] - $q->[1] * $p->[2]) % $P) != 0;
    return 1;
}
sub decompress {
    my $raw = $_[0];
    my $y = leint($raw);
    my $sign = ($y >> 255)->is_odd ? 1 : 0;
    $y = $y % bn(2)->bpow(255);
    return undef if $y >= $P;
    my $x2 = (($y * $y - 1) * inv($D * $y * $y + 1)) % $P;
    my $x;
    if ($x2->is_zero) {
        return undef if $sign;
        $x = bn(0);
    } else {
        $x = $x2->copy->bmodpow(bdivs($P + 3, 8), $P);
        $x = ($x * $I) % $P if (($x * $x - $x2) % $P) != 0;
        return undef if (($x * $x - $x2) % $P) != 0;
        $x = $P - $x if ($x->is_odd ? 1 : 0) != $sign;
    }
    return [$x, $y, bn(1), ($x * $y) % $P];
}

my $result = eval {
    my $pub = pack('H*', $pubhex);
    my $sig = slurp($sigf);
    my $msg = slurp($msgf);
    return 0 unless length($pub) == 32 && length($sig) == 64;
    my $A = decompress($pub) or return 0;
    my $R = decompress(substr($sig, 0, 32)) or return 0;
    my $S = leint(substr($sig, 32, 32));
    return 0 if $S >= $L;
    my $k = leint(sha512(substr($sig, 0, 32) . $pub . $msg)) % $L;
    my $B = decompress(pack('H*', '5866666666666666666666666666666666666666666666666666666666666666')) or return 0;
    return peq(pmul($S, $B), padd($R, pmul($k, $A)));
};
exit(($result // 0) ? 0 : 1);
