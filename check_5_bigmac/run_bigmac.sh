RESULTS_DIR="analysis_results"

if [ $# -eq 0 ]
  then
    echo "Usage: compare.sh <fw1.zip> <fw2.zip> <vendor>"
    exit 1
fi
fw1=$1
fw2=$2
vendor=$3

echo "fw1: $fw1"
echo "fw2: $fw2"
echo "vendor: $vendor"

mkdir "${RESULTS_DIR}"

python3 ./docker_automation.py extract $fw1 $vendor analysis_results/ss1.paths analysis_results/uapps1.paths  analysis_results/ns1.paths
python3 ./docker_automation.py extract $fw2 $vendor analysis_results/ss2.paths analysis_results/uapps2.paths  analysis_results/ns2.paths