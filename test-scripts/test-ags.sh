#!/bin/bash
# Executes a bunch of regression tests attack graphs. These test scripts include:
#   - stats-ff.sh
#   - compare-ag-dirs.sh
#   - diff-ags.sh
#     - diff-nodes.sh
#     - diff-edges.sh
#   - stats-nodes-ags.sh
#   - stats-sinks.sh
#
# NB! This script is based on .dot files, which are by default deleted during the execution of SAGE.
#      To prevent the deletion, use the --keep-files option when running SAGE.

set -euo pipefail
IFS=$'\n\t'

umask 077


function usage(){
    echo -e "Usage: $0 [-i] ExpName1 ExpName2\n\n\t-i\tremove node IDs when comparing the attack graphs"
}


option_i=
if [[ $# -eq 2 ]]; then
    # Experiment names that have been used to run SAGE
    orig_exp_name="$1"
    updated_exp_name="$2"
elif [[ $# -eq 3 ]] && [[ "$1" == "-i" ]] ; then
    option_i="-i"
    orig_exp_name="$2"
    updated_exp_name="$3"
# The number of arguments can only be two or three; if three arguments, the first one must be -i option
else
    usage >&2
    exit 1
fi

# Resolve the FlexFringe files based on the experiment name
orig_traces="${orig_exp_name}.txt"
updated_traces="${updated_exp_name}.txt"

# Check if these FlexFringe files exist
! [[ -f "$orig_traces" ]] && { echo "$0: file $orig_traces does not exits" >&2 ; exit 1 ; }
! [[ -f "$updated_traces" ]] && { echo "$0: file $updated_traces does not exits" >&2 ; exit 1 ; }

# Resolve the directories with the attack graphs
orig_ags="${orig_exp_name}AGs/"
updated_ags="${updated_exp_name}AGs/"

# Check if this directory exists
! [[ -d "$orig_ags" ]] && { echo "$0: directory $orig_ags does not exist" >&2 ; exit 1 ; }
! [[ -d "$updated_ags" ]] && { echo "$0: directory $updated_ags does not exist" >&2 ; exit 1 ; }

passed_tests=0
total_tests=0

echo "Test 1: Performing diffs on traces"
diff -q "$orig_traces" "$updated_traces" && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"


echo "Test 2: Performing diffs on FlexFringe stats"
./stats-ff.sh "$orig_exp_name" > /dev/null  # Check for potential errors that will not be caught because of process substitution
./stats-ff.sh "$updated_exp_name" > /dev/null
diff <(./stats-ff.sh "$orig_exp_name") <(./stats-ff.sh "$updated_exp_name") && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"


echo "Test 3: Comparing directories"
./compare-ag-dirs.sh "$orig_ags" "$updated_ags" && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"


echo "Test 4: Performing diffs on AGs"
./diff-ags.sh $option_i "$orig_ags" "$updated_ags" && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"


echo "Test 5: Checking node stats"
./stats-ff.sh "$orig_exp_name" > /dev/null
./stats-ff.sh "$updated_exp_name" > /dev/null
diff -q <(./stats-nodes-ags.sh "$orig_ags") <(./stats-nodes-ags.sh "$updated_ags") && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"


echo "Test 6: Checking sinks stats"
./stats-sinks-ags.sh -t "$orig_ags" "$updated_ags" && { echo "Passed" ; passed_tests=$((passed_tests + 1)) ; } || echo "Failed"
total_tests=$((total_tests + 1))
echo "------------"

echo "Tests passed: ${passed_tests}/${total_tests}"

[[ "$passed_tests" -eq "$total_tests" ]] && exit 0 || exit 1
