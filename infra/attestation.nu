# ACE Tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
# FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
# MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
# for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
# distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
#
# DM26-0670

# What the attestation agent says of itself, for a bring-up to report (docs/architecture/attestation-when-it-cannot-answer.md, "The agent proves itself").
# It reports and never stops a run: an agent that doubts itself answers that it cannot say, and the deployment goes on, unattested.

# The last thing the agent said of itself in these log lines, as { verdict, line }: "proved", "doubts", "waiting" or "unknown".
export def attestation_report [lines: list<string>]: nothing -> record {
    let said = ($lines
        | each {|l| $l | ansi strip }
        | where {|l| ($l | str contains "it has proved itself") or ($l | str contains "it doubts itself") or ($l | str contains "it cannot say yet") })
    if ($said | is-empty) {
        return { verdict: "unknown", line: "the attestation agent has said nothing of itself yet: kubectl logs -n polar deploy/attestation-agent -c attestation-agent" }
    }
    let last = ($said | last)
    if ($last | str contains "it has proved itself") {
        { verdict: "proved", line: "the attestation agent has proved itself: its verdicts stand" }
    } else {
        let why = ($last | str replace --regex '^.*(gone|yet): ' '')
        if ($last | str contains "it doubts itself") {
            { verdict: "doubts", line: $"the attestation agent doubts itself, so certificates are issued unattested until this has gone: ($why)" }
        } else {
            { verdict: "waiting", line: $"the attestation agent cannot say yet: ($why)" }
        }
    }
}
