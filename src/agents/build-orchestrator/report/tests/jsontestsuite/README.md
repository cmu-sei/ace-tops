<!--
ACE Tool

Copyright 2026 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Licensed under a MIT (SEI)-style license, please see license.txt or contact
permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
distribution.  Please see Copyright notice for non-US Government use and distribution.

This Software includes and/or makes use of Third-Party Software each subject to its own license.

DM26-0670
-->

# JSONTestSuite's parsing cases

The `test_parsing` files of [JSONTestSuite](https://github.com/nst/JSONTestSuite), at commit
`1ef36fa01286573e846ac449e8683f8833c5b26a` (fetched 2026-11-08, Nix hash
`sha256-s2yMgVWq2DwibAjOvLKhGDbEwXm4yke/g4mp7u565H4=`), the corpus behind Nicolas Seriot's "Parsing JSON is a Minefield".
Third-party, under its own MIT license (`LICENSE`), unchanged.

Each case is named for what a JSON parser must do with it: `y_` accept, `n_` refuse, `i_` either. `tests/jsontestsuite.rs`
holds the report reader to it: no `n_` case passes the gate and the parser; a `y_` case is refused only for what the report
grammar leaves out on purpose; no case of any kind makes the gate, the parser or the check panic.

First run, 2026-11-08: all 188 `n_` refused; of the 95 `y_`, 65 read, and 30 refused for what the grammar leaves out (22
outside it: booleans, signs, fractions and exponents; 6 holding a raw newline or DEL; 2 with a key twice); the 35 `i_` and
everything else without a panic.
