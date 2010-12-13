$i = 0;
while (<>)
{
    next if (!(/^#define[\s]+(CAP_[A-Z_0-9]+)[\s]+([0-9]+)[\s]*$/));
    print "\t/* $i */ CAP_STRING(\"\"),\n" while (++$i <= $2);
    my $cap = $1;
    $cap =~ s/^CAP_//;
    print "\t/* $2 */ CAP_STRING(\"\L$cap\E\"),\n";
}

