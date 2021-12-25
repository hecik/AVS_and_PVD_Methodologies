#!/bin/bash

if [ $# -eq 0 ]
then
    Usage	: $0 <CVE List File Path>
    exit
fi

while IFS="" read -r cve_line
do
    sql_string_cve="select value from nvd_descriptions
    inner join nvds
    on nvds.id = nvd_id
    where cve_id='$cve_line'"

    echo -e "**************************************************************************" >>descript_result
    echo $cve_line >>descript_result
    echo -e "**************************************************************************" >>descript_result
    echo -e "$sql_string_cve" | sqlite3 ./cve.sqlite3 >>descript_result
    echo -e "**************************************************************************\n\n" >>descript_result

done < "$1"
