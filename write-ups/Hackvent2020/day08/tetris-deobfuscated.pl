use Term::ReadKey;
ReadMode 5;
$ |= 1;

print "\ec\e[2J\e[?25l\e[?7l\e[1;1H\e[0;0r";

@FF = split	//,'####H#V#2#0#{#h#t#t#p#s#:#/#/#w#w#w#.#y#o#u#t#u#b#e#.#c#o#m#/#w#a#t#c#h#?#v#=#d#Q#w#4#w#9#W#g#X#c#Q#}####';

# Block types
@BB=(89,51,30,27,75,294);

# Print the yellow border
$w=11;
$h=23;
print("\e[1;1H\e[103m".(' 'x(2*$w+2))."\e[0m\r\n".(("\e[103m \e[0m".(' 'x(2*$w))."\e[103m \e[0m\r\n")x$h)."\e[103m".(' 'x(2*$w+2))."\e[2;1H\e[0m");

# Blocks
sub bl {
  ($b, $bc, $bcc, $x, $y) = @_; # b: block type, bc: letter, bcc: ?
  for $yy (0..2) {
    for $xx (0..5) {
      print("\e[${bcc}m\e[".($yy+$y+2).";".($xx+$x*2+2)."H${bc}")
      if ( (($b & (0b111<<($yy*3))) >> ($yy*3)) & ( 4 >> ($xx>>1) ));
}}}

# Rotate block
sub r {
  $_=shift;
  ($_&4)<<6|($_&32)<<2|($_&256)>>2|($_&2)<<4|($_&16)|($_&128)>>4|($_&1)<<2|($_&8)>>2|($_&64)>>6;
}

sub _s {
  ($b,$bc,$x,$y)=@_;
  for $yy (0..2) {
    for $xx (0..5) {
      substr($f[$yy+$y],($xx+$x),1)=$bc
      if(((($b & (0b111<<($yy*3)))>>($yy*3))&(4>>$xx)));
  }}
  $Q='QcXgWw9d4';
  @f=grep{/ /}@f;
  unshift @f,(" "x$w)while(@f<$h);
  p();
}

# Check game board boundaries
sub cb{
  $_Q='ljhc0hsA5';
  ($b,$x,$y)=@_;
  for $yy (0..2) {
    for $xx (0..2) {
      return 1 if (((($b&(0b111<<($yy*3)))>>($yy*3))&(4>>$xx))&&(($yy+$y>=$h)||($xx+$x<0)||($xx+$x>=$w)||(substr($f[$yy+$y],($xx+$x),1) ne ' ')));
}}}

# ???
sub p {
  for $yy (0..$#f) { # It was $#f ???
    print("\e[".($yy+2).";2H\e[0m");
    $_=$f[$yy];
    s/./$&$&/gg;
    print;
}};

# Get pressed key
sub k {
  $k='';
  $k.=$c while($c=ReadKey(-1));
  $k;
};

# New block
sub n {
  $bx=5; # Start X position
  $by=0;
  $bi=int(rand(scalar @BB)); # Random block type
  $__=$BB[$bi];
  $_b=$FF[$sc]; # Block letter
  # What is this !!!
  $sc > 77 && $sc <98 && $sc != 82 && eval('$_b'."=~y#$Q#$_Q#") || $sc==98 && $_b=~s/./0/;
  $sc++; # Step counter
}

@f=(" "x$w)x$h;
p();
n();

while(1) {
  $k=k();
  last if($k=~/q/); # q for Quit
  $k=substr($k,2,1);
  $dx=($k eq 'C')-($k eq 'D'); # dx: Left or right (-1/0/1)
  #print "A:$dx";
  $bx+=$dx unless(cb($__,$bx+$dx,$by)); # bx: Left or right offset
  #print "B:$bx";
  if($k eq 'A'){ # Rotation
    #print "W";
    unless(cb(r($__),$bx,$by)){
      $__=r($__)
    } elsif (!cb(r($__),$bx+1,$by)) {
      $__=r($__);
      $bx++
    } elsif(!cb(r($__),$bx-1,$by)){
      $__=r($__);
      $bx--
    };
  }
  bl($__,$_b,101+$bi,$bx,$by); # Blocks
  select(undef,undef,undef,0.1); # Game speed
  if (cb($__,$bx,++$by)) {
    #print "X";
    last if($by<2);
    _s($__,$_b,$bx,$by-1); # Blocks fall through each other
    n(); # New block
  } else {
    #print "Y";
    bl($__," ",0,$bx,$by-1);
  }
}

sleep(1);
ReadMode 0;
print"\ec";
