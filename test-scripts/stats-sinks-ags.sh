#!/bin/bash
# Compares two directories with attack graphs in terms of sink and non-sink nodes.
# It performs a left outer join on nodes from two directories.
#   If a node is absent in the second directory, "-" will be written, which indicates that this node has been merged.
#   If a node is present in both directories, its status ("sink" or "non-sink") will be printed for both directories.
#
# Example output:
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 1083    sink      -
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 1097    sink      -
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 11      sink      -
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 288     non-sink  non-sink
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 673     sink      -
#   ARBITRARY CODE EXECUTION|microsoft-ds | ID: 853     sink      -
#
# If running in a diff/test mode (i.e. option -t), only the states that differ are printed (e.g. sinks -> non-sink),
#   and the corresponding exit code is returned (0 if no changes, otherwise 1).
# This mode can be used for regression tests, i.e. to make sure that the sink states in the attack graphs
#   have not been affected by the changes in the code (assuming the changes in the code do not affect the graphs).
#
# NB! This script is based on .dot files, which are by default deleted during the execution of SAGE.
#      To prevent the deletion, use the --keep-files option when running SAGE.

set -euo pipefail
IFS=$'\n\t'

umask 077

function usage(){
    echo -e "Usage: $0 [-t] path/to/AGs path/to/AGs\n\n\t-t\tperform a diff (i.e. test) and print only the states that differ"
}

function get_states() {
    find "$1" -type f -name '*.dot' |                                   # Find all the .dot files in the provided directory
    xargs gvpr '
        N {
            string sink = "non-sink";
            if (index($.style, "dotted") != -1) sink = "sink";          // Check whether the node is a sink or a non-sink node
            print(gsub(gsub($.name, "\r"), "\n", "|") + "\t" + sink);   // Print everything on one line
        }' |
        grep -v '^Victim' |                                             # Remove the artificial root nodes (start with "Victim: ")
        sort -u -t $'\t' -k1,1                                          # Sort by name and ID, removing duplicate nodes
}

mode="normal"
if [[ $# -eq 2 ]]; then
    original=$(echo "$1/" | tr -s '/')
    modified=$(echo "$2/" | tr -s '/')
elif [[ $# -eq 3 ]] && [[ "$1" == "-t" ]] ; then
    mode="test"
    original=$(echo "$2/" | tr -s '/')
    modified=$(echo "$3/" | tr -s '/')
# The number of arguments can only be two or three; if three arguments, the first one must be -t option
else
    usage >&2
    exit 1
fi

# Check if all input directories exist
! [[ -d "$original" ]] && { echo "$0: directory $original does not exist" >&2 ; exit 1 ; }
! [[ -d "$modified" ]] && { echo "$0: directory $modified does not exist" >&2 ; exit 1 ; }


# When running in diff/test mode, report the change
if [[ "$mode" == "test" ]]; then
    changes=$(join -t $'\t' -a1 -e "-" -o'0,1.2,2.2' <(get_states "$original") <(get_states "$modified") | 
        column -t -s $'\t' |                # Align tabs to produce better-looking output
        awk '$(NF-1) != $NF { print }')     # Filter sink nodes that have become non-sinks
    [[ -n "$changes" ]] && { echo -e "$changes" ; exit 1 ; }
    exit 0
fi

# Perform a left-outer join based on the node name and ID
join -t $'\t' -a1 -e "-" -o'0,1.2,2.2' <(get_states "$original") <(get_states "$modified") |    # Join nodes from both directories based on their names and IDs (first field, separated by '\t')
    column -t -s $'\t' #|                                                                       # Align tabs to produce better-looking output
    #awk '$(NF-1) == "sink" && $NF == "non-sink" { print }'                                     # Filter sink nodes that have become non-sinks
    #awk '$(NF-1) == "sink" && $NF == "-" { print }'                                            # Filter sink nodes that have been merged
    #awk '$(NF-1) == "non-sink" && $NF == "non-sink" { print }'                                 # Filter non-sink nodes that have remained after merging

