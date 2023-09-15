#!/bin/bash
# Computes the statistics on nodes for a directory with AGs.
# The computed statistics are:
#   - Total number of nodes across all the AGs in the provided directory
#   - Number of unique nodes across all the AGs in the provided directory
#       (root counts as a unique node even if it appears somewhere in another graph)
#   - Total number of sink nodes across all the AGs in the provided directory (and their percentage)
#   - Number of unique sink nodes across all the AGs in the provided directory (and their percentage)
#
# NB! This script is based on .dot files, which are by default deleted during the execution of SAGE.
#      To prevent the deletion, use the --keep-files option when running SAGE.

set -euo pipefail
IFS=$'\n\t'

umask 077

function usage(){
    echo "Usage: $0 AGs/"
}

# Check if exactly one argument is provided
[[ $# -ne 1 ]] && { usage >&2 ; exit 1; }

# Check if the input directory exists
dir=$(echo "$1/" | tr -s '/')
! [[ -d "$dir" ]] && { echo "$0: directory $dir does not exist" >&2 ; exit 1 ; }

# Compute the node counts from the AGs. Sink nodes have "dotted" in their style attribute. Start nodes have "yellow" fillcolor. Objective variants are hexagon-shaped and have "salmon" fillcolor
nodes_total=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | wc -l)
nodes_unique=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | sort -u | wc -l)
sinks_total=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ index($.style, "dotted") != -1 ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | wc -l)
sinks_unique=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ index($.style, "dotted") != -1 ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | sort -u | wc -l)
ags_with_sinks=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'BEG_G { int count = 0; } N [ index($.style, "dotted") != -1 ] { count += 1; } END_G { if (count > 0) print(gsub(gsub($G.name, "\r"), "\n", "|")); }' | wc -l)
start_nodes=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ $.fillcolor == "yellow" ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | wc -l)
objective_variants=$(find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ $.shape == "hexagon" && fillcolor == "salmon" ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | wc -l)

# Print the computed node counts, as well as the persentage for the sink nodes
echo "Total number of nodes: $nodes_total"
echo "Number of unique nodes: $nodes_unique"
echo "Total number of sink nodes: $sinks_total ($(echo "scale=3; 100 * $sinks_total / $nodes_total" | bc)%)"
echo "Number of unique sink nodes: $sinks_unique ($(echo "scale=3; 100 * $sinks_unique / $nodes_unique" | bc)%)"
echo "Number of AGs with sinks: $ags_with_sinks"
echo "Number of start nodes: $start_nodes"
echo "Number of objective variants: $objective_variants"

# Comment out to print all the shapes that sinks nodes have
# echo -ne "Shapes of sink-nodes: " ; find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ index($.style, "dotted") != -1 ] { print($.shape); }' | sort -u | paste -sd ','

# Comment out to print all unique nodes
# find "$dir" -type f -name '*.dot' | xargs gvpr 'N { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | sort -u

# Comment out to print all unique sink nodes
# find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ index($.style, "dotted") != -1 ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | sort -u

# Comment out to print all unique non-sink nodes
# find "$dir" -type f -name '*.dot' | xargs gvpr 'N [ index($.style, "dotted") == -1 ] { print(gsub(gsub($.name, "\r"), "\n", "|")); }' | sort -u

