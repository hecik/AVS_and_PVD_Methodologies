#!/bin/bash

if [ $# -eq 0 ]
then
    echo "
    If conduct PVD Result Analysis;
    
    Usage	: $0 <CPE List File Path> <Software Version> <AS_TP Result Path>
    Example	: $0 ./software_cpe_list 1.1.2 ./AS_TP_Result

    If only search CVEs from NVD DBs then use;

    Example	: $0 ./software_cpe_list 1.1.2"
    exit
fi

exact_software_version="$2"
software_name=$(cat  "$1" | cut -d ":" -f 5 | head -n 1)

while IFS="" read -r ps_cpe_line
do

    sql_string_all="select  cve_id||','||version_start_excluding||','||version_start_including||','||version_end_excluding||','||version_end_including from nvds
    inner join nvd_cpes
    on nvd_cpes.nvd_id = nvds.id
    where formatted_string='$ps_cpe_line'"


    echo -e ".mode column\n.headers on\n$sql_string_all;\n" | sqlite3 ./cve.sqlite3 >passive_scan_result


    result_gt=''
    result_lt=''
    result_eq=''
    function version_gt
    {
        var1=$(echo "$@" | tr " " "\n" | sort -V | head -n 1)

        if [ "$var1" = "$2" ] && [ "$var1" != "$1" ]; then
            #echo "Strings are bigger"
            result_gt='bigger'

        fi
    }

    function version_lt
    {
        var1=$(echo "$@" | tr " " "\n" | sort -V | head -n 1)

        if [ "$var1" = "$1" ] && [ "$var1" != "$2" ]; then
            #echo "String is lower"
            result_lt='lower'

        fi
    }
    function version_eq
    {
        var1=$(echo "$@" | tr " " "\n" | sort -V | head -n 1)

        if [ "$var1" = "$1" ] && [ "$var1" = "$2" ]; then
            #echo "String is equal"
            result_eq='equal'

        fi
    }
    sed '1,2d' ./passive_scan_result | while IFS="" read -r cve_line
    do

        cve_id=$(echo  $cve_line | cut -d "," -f 1)
        version_start_excluding=$(echo  $cve_line | cut -d "," -f 2)
        version_start_including=$(echo  $cve_line | cut -d "," -f 3)
        version_end_excluding=$(echo  $cve_line | cut -d "," -f 4)
        version_end_including=$(echo  $cve_line | cut -d "," -f 5)

        if [ -z  $version_start_excluding ]; then version_start_excluding=0;fi
        if [ -z  $version_start_including ]; then version_start_including=0;fi

        echo "Software CVE ID		:" $cve_id
        echo "Version Start Excluding	:" $version_start_excluding
        echo "Version Start Including	:" $version_start_including
        echo "Version End Excluding	:" $version_end_excluding
        echo "Version End Including	:" $version_end_including
        echo "Software Exact Version	:" $exact_software_version
        echo "*********************************************************"

        version_lt $version_start_excluding $exact_software_version
        if  [ "$result_lt" = "lower" ];then
            result_lt=''
            version_lt $version_start_including $exact_software_version
            version_eq $version_start_including $exact_software_version

            if [ "$result_lt" = "lower" ] || [ "$result_eq" = "equal" ];then
                result_lt=''
                result_eq=''

                if [ -z  $version_end_excluding ];then

                    version_gt $version_end_including $exact_software_version
                    version_eq $version_end_including $exact_software_version

                    if [ "$result_gt" = "bigger" ] || [ "$result_eq" = "equal" ];then
                        result_gt=''
                        result_eq=''
                        echo $cve_id >>software_PS_cve_result_temp
                    fi
                    if [ -z $version_end_including ];then

                        echo $cve_id >>software_PS_cve_result_temp
                    fi
                fi
                version_gt $version_end_excluding $exact_software_version

                if [ -n  $version_end_excluding ] && [ "$result_gt" = "bigger" ];then

                    result_gt=''
                    echo $cve_id >>software_PS_cve_result_temp
                fi
            fi
        fi

        result_gt=''
        result_lt=''
        result_eq=''
    done
done < "$1"
direct=results/$software_name
mkdir -p $direct
sort -u software_PS_cve_result_temp >./$direct/${software_name}_PS_cve_result
rm -rf software_PS_cve_result_temp passive_scan_result

if [ -z $3  ]
then
    echo "
    If conduct PVD algorithm;
    Please insert  3.rd parameter AS_TP Results File Directory Path

    Usage	: $0 <CPE List File Path> <Software Version> <AS_TP Result Path>
    Example	: $0 ./software_cpe_list 1.1.2 ./AS_TP_Result"

    exit
else
	comm -23 <(sort -u $3) ./$direct/${software_name}_PS_cve_result >./$direct/${software_name}_PS_State3_FS1
	comm -13 <(sort -u $3) ./$direct/${software_name}_PS_cve_result >./$direct/${software_name}_PS_State4
	comm -12 <(sort -u $3) ./$direct/${software_name}_PS_cve_result >./$direct/${software_name}_PS_State5_FS2
fi
