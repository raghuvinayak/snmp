#!/usr/bin/perl

use NetSNMP::agent (':all');
use NetSNMP::ASN;
use NetSNMP::OID;
$| = 1; #disable the output buffering
sub hello_handler{
  my ($handler, $registration_info, $request_info, $requests) = @_;
  my $request;
  my $string_value = "requested OID is out of range";
  for($request = $requests; $request; $request = $request->next()) {
    my $oid = $request->getOID();
    if ($request_info->getMode() == MODE_GET){
         if ($oid == new NetSNMP::OID("1.3.6.1.4.1.4171.40.1")) {
              $request->setValue(ASN_COUNTER,time);}
         if ($oid > new NetSNMP::OID("1.3.6.1.4.1.4171.40.1")) {
my @c1 = split /[.]/, $oid ;
my $last = $c1[-1];
@counter_values = `cat /usr/share/snmp/counters.conf`; $val = $last - 2;
my @c = split /[,]/,$counter_values[$val]; my $val = $c[-1];
my $tim = time;
my $y = $tim * $val ;
$max = 2**32;
if ($y >= $max){
$st = 0x00000000FFFFFFFF;
my $counter_value = $y & $st ;
$request->setValue(ASN_COUNTER,$counter_value);}
else {
my $counter_value = $y;
$request->setValue(ASN_COUNTER,$counter_value);}
if (!$y){
my $counter_string = "Requested OID is out of range. ";
$request->setValue(ASN_OCTET_STR,$counter_string);}}

}}}

my $agent = new NetSNMP::agent();
$agent->register("test_agent", "1.3.6.1.4.1.4171.40",
                 \&hello_handler);


