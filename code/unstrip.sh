# please change the paths according to your environment!
stripped="/home/valeriop/Scrivania/SATCS_proj/ds/executable/train"
debug="/home/valeriop/Scrivania/SATCS_proj/ds/debug/train"
output_dir="/home/valeriop/Scrivania/SATCS_proj/dataset_unstripped/"
for file in $stripped/*
do
	file=${file} # path to stripped file
	filename=${file#$stripped/} # name of file
	#echo $file
	#echo $filename
	if [ -f $debug/$filename ] # check if debug file exists
	then
		#echo $debug/$filename
		eu-unstrip $file $debug/$filename --force --output=$output_dir$filename
	fi
done
	
