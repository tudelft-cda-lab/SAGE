#!/bin/bash
# Compares two directories with AGs (presumably, generated by original and modified SAGE algorithm respectively).
# Prints how many AGs are present in each directory, how many AGs are present in both directories,
#   and how many AGs are present only in the first and only in the second directories.
# If at least one AG is present in only in one of the directories, it is also printed.
#
# NB! This script is based on .dot files, which are by default deleted during the execution of SAGE.
#      To prevent the deletion, use the --keep-files option when running SAGE.

set -euo pipefail
IFS=$'\n\t'

umask 077

function usage(){
    echo "Usage: $0 path/to/AGs path/to/AGs"
}

# Check if exactly two arguments are provided
[[ $# -ne 2 ]] && { usage >&2 ; exit 1; }

# Check if all input directories exist
original=$(echo $1/ | tr -s '/')
modified=$(echo $2/ | tr -s '/')
! [[ -d "$original" ]] && { echo "$0: directory $original does not exist" >&2 ; exit 1 ; }
! [[ -d "$modified" ]] && { echo "$0: directory $modified does not exist" >&2 ; exit 1 ; }

# Find the generated AGs for each input directory
original_ags=$(find "$original" -type f -name '*.dot' -printf '%f\n' | sed 's/^.*attack-graph-for-victim-\(.*\)$/\1/' | sed 's/\.dot$//' | sort)
modified_ags=$(find "$modified" -type f -name '*.dot' -printf '%f\n' | sed 's/^.*attack-graph-for-victim-\(.*\)$/\1/' | sed 's/\.dot$//' | sort)

# Print the number of generated attack graphs for each input directory
echo "Total number of AGs generated by the original algorithm: $(echo -e "$original_ags" | wc -l)"
echo "Total number of AGs generated by the modified algorithm: $(echo -e "$modified_ags" | wc -l)"

# Print the number of AGs generated by both algorithms (comment out `| wc -l` if you want to see which AGs these are)
echo -n "Number of AGs generated both by the original and the modified algorithms: "
comm -12 <(echo -e "$original_ags") <(echo -e "$modified_ags") | wc -l

# Print the number of attack graphs generated only by the original algorithm (and the AGs if there is at least one)
echo -n "Number of AGs generated only by the original algorithm: "
only_original=$(comm -23 <(echo -e "$original_ags") <(echo -e "$modified_ags") | wc -l)
echo "$only_original"
if [[ $only_original -ne 0 ]]; then
    echo "AGs generated only by the original algorithm: "
    comm -23 <(echo -e "$original_ags") <(echo -e "$modified_ags")
fi

# Print the number of attack graphs generated only by the modified algorithm (and the AGs if there is at least one)
echo -n "Number of AGs generated only by the modified algorithm: "
only_modified=$(comm -13 <(echo -e "$original_ags") <(echo -e "$modified_ags") | wc -l)
echo "$only_modified"
if [[ $only_modified -ne 0 ]]; then
    echo "AGs generated only by the modified algorithm: "
    comm -13 <(echo -e "$original_ags") <(echo -e "$modified_ags")
fi

# Exit with 0 if the directories are the same in terms of the generated AGs, otherwise exit with 1
if [[ "$only_original" -eq 0 ]] && [[ "$only_modified" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
