#!/usr/bin/perl
# Одноразовый код TOTP (RFC 6238) из секрета на stdin.
# Секрет — base32 (пробелы и регистр не важны) или ссылка otpauth://totp/...;
# из ссылки берутся secret, algorithm, digits, period.
# Usage: printf '%s' "$secret" | totp.pl [unix-время]
use strict;
use warnings;
use Digest::SHA qw(hmac_sha1 hmac_sha256 hmac_sha512);

my $input = do { local $/; <STDIN> } // '';
$input =~ s/^\s+|\s+$//g;

my %opt = (algorithm => 'SHA1', digits => 6, period => 30);
my $secret = $input;
if ($input =~ m{^otpauth://}i) {
	my ($query) = $input =~ /\?(.*)$/ or die "totp: в ссылке нет параметров\n";
	my %q;
	for (split /&/, $query) {
		my ($k, $v) = split /=/, $_, 2;
		$v //= '';
		$v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
		$q{lc $k} = $v;
	}
	$secret = $q{secret} // die "totp: в ссылке нет secret\n";
	$opt{$_} = $q{$_} for grep { defined $q{$_} && length $q{$_} } keys %opt;
}

$secret = uc $secret;
$secret =~ s/[\s=-]//g;
die "totp: секрет пуст или не base32\n" unless $secret =~ /^[A-Z2-7]+$/;

my $bits = join '', map { sprintf '%05b', index 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $_ } split //, $secret;
$bits = substr $bits, 0, length($bits) - length($bits) % 8;
my $key = pack 'B*', $bits;

my %hmac = (SHA1 => \&hmac_sha1, SHA256 => \&hmac_sha256, SHA512 => \&hmac_sha512);
my $h = $hmac{uc $opt{algorithm}} or die "totp: алгоритм $opt{algorithm} не поддержан\n";
die "totp: digits должно быть 6-8\n" unless $opt{digits} =~ /^[6-8]$/;
die "totp: period должен быть положительным числом\n" unless $opt{period} =~ /^\d+$/ && $opt{period} > 0;

my $now = defined $ARGV[0] ? $ARGV[0] : time;
my $counter = int($now / $opt{period});
my $mac = $h->(pack('Q>', $counter), $key);
my $off = ord(substr $mac, -1) & 0x0f;
my $bin = unpack('N', substr $mac, $off, 4) & 0x7fffffff;
printf "%0*d\n", $opt{digits}, $bin % (10**$opt{digits});
