#!/bin/bash
# Download all research papers for the Autonomous Purple Teaming project
# Run this script from a machine with unrestricted internet access.
# Usage: chmod +x download_papers.sh && ./download_papers.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "Downloading papers to: $DIR"
echo "==========================================="

download() {
    local url="$1"
    local filename="$2"
    local description="$3"

    if [ -f "$filename" ]; then
        echo "[SKIP] $description -- already exists"
        return 0
    fi

    echo "[DOWNLOADING] $description"
    if curl -L --connect-timeout 30 --max-time 120 -o "$filename" "$url" 2>/dev/null; then
        # Verify it's actually a PDF (check magic bytes)
        if head -c 4 "$filename" | grep -q '%PDF'; then
            echo "[OK] $filename"
        else
            echo "[WARN] $filename downloaded but may not be a valid PDF"
        fi
    else
        echo "[FAIL] $description"
        rm -f "$filename"
    fi
}

download "https://arxiv.org/pdf/2308.06782" \
    "PentestGPT_2308.06782.pdf" \
    "1. PentestGPT (2308.06782)"

download "https://arxiv.org/pdf/2410.03225" \
    "AutoPenBench_2410.03225.pdf" \
    "2. AutoPenBench (2410.03225)"

download "https://arxiv.org/pdf/2412.01778" \
    "HackSynth_2412.01778.pdf" \
    "3. HackSynth (2412.01778)"

download "https://arxiv.org/pdf/2411.05185" \
    "PentestAgent_2411.05185.pdf" \
    "4. PentestAgent (2411.05185)"

download "https://arxiv.org/pdf/2505.10321" \
    "AutoPentest_Henke_2505.10321.pdf" \
    "5. AutoPentest - Henke (2505.10321)"

download "https://arxiv.org/pdf/2501.13411" \
    "VulnBot_2501.13411.pdf" \
    "6. VulnBot (2501.13411)"

download "https://arxiv.org/pdf/2505.06913" \
    "RedTeamLLM_2505.06913.pdf" \
    "7. RedTeamLLM (2505.06913)"

download "https://arxiv.org/pdf/2512.11143" \
    "AutoPentest_Classical_Planning_2512.11143.pdf" \
    "8. Automated Pentest with Classical Planning (2512.11143)"

download "https://arxiv.org/pdf/2305.17246" \
    "NASimEmu_2305.17246.pdf" \
    "9. NASimEmu (2305.17246)"

download "https://arxiv.org/pdf/2304.01244" \
    "CyGIL_2304.01244.pdf" \
    "10. CyGIL (2304.01244)"

download "https://arxiv.org/pdf/2309.03292" \
    "CSLE_Recursive_Decomposition_2309.03292.pdf" \
    "11. CSLE Recursive Decomposition (2309.03292)"

download "https://arxiv.org/pdf/2601.05293" \
    "Survey_Agentic_AI_Cybersecurity_2601.05293.pdf" \
    "12. Survey of Agentic AI and Cybersecurity (2601.05293)"

download "https://arxiv.org/pdf/2505.12786" \
    "LLM_Agents_Cyberattacks_Survey_2505.12786.pdf" \
    "13. LLM Agents in Autonomous Cyberattacks Survey (2505.12786)"

download "https://arxiv.org/pdf/2505.04843" \
    "LLMs_Autonomous_Cyber_Defenders_2505.04843.pdf" \
    "14. LLMs as Autonomous Cyber Defenders (2505.04843)"

download "https://arxiv.org/pdf/2511.09114" \
    "Generalisable_Cyber_Defence_Agent_2511.09114.pdf" \
    "15. Towards Generalisable Cyber Defence Agent (2511.09114)"

download "https://arxiv.org/pdf/2508.19278" \
    "Production_Worthy_Simulation_ACO_2508.19278.pdf" \
    "16. Production-Worthy Simulation for ACO (2508.19278)"

download "https://arxiv.org/pdf/2410.17351" \
    "CAGE4_Hierarchical_MARL_2410.17351.pdf" \
    "17. CAGE-4 Hierarchical MARL (2410.17351)"

download "https://arxiv.org/pdf/2510.24317" \
    "CAIBench_2510.24317.pdf" \
    "18. CAIBench (2510.24317)"

download "https://arxiv.org/pdf/2307.04416" \
    "Automated_Cyber_Range_Design_2307.04416.pdf" \
    "19. Towards Automated Cyber Range Design (2307.04416)"

download "https://arxiv.org/pdf/2509.11398" \
    "Firewalls_to_Frontiers_CMU_SEI_2509.11398.pdf" \
    "20. From Firewalls to Frontiers - CMU SEI (2509.11398)"

echo ""
echo "==========================================="
echo "Download complete. Check above for any failures."
echo "Successfully downloaded PDFs:"
ls -la "$DIR"/*.pdf 2>/dev/null | wc -l
