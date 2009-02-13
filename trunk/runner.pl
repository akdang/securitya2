
for($i = 0; $i<3; $i++)
{
    $input = "";
    $inputSize = ""; 
if($i == 0)
{
$input = "HalInstructions";
}
elsif($i == 1)
{
$input = "shakes.txt";
}
else
{
$input = "tabTest";
}
    $inputSize = `wc -c $input`;
    print "running w/ input file $input ($inputSize bytes)\n";
    for($j = 0; $j < 3; $j++)
    {
        $output = `java ConcSecureSystem $input`;
        print $output;    
    }
    print "\n";
}
