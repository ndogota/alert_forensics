// The eight scenarios in the order docs/SPEC.md numbers them, with the one-line
// gloss the spec gives each. The number is the spec's label for the scenario,
// not a measurement; every measured number on the page comes from the matrix
// file or a committed recording. The alert title and the truth come from the
// matrix file's metadata, not from here.

export interface ScenarioGloss {
  id: string;
  number: number;
  gloss: string;
  trap: boolean;
}

export const SCENARIOS: ScenarioGloss[] = [
  {
    id: "atypical_travel",
    number: 1,
    gloss: "Paris to Amsterdam within the hour. It is the group SASE gateway.",
    trap: false,
  },
  {
    id: "password_spray",
    number: 2,
    gloss: "Spray across the tenant, one success, then a new MFA method and a mailbox rule.",
    trap: false,
  },
  {
    id: "forwarding_rule",
    number: 3,
    gloss: "Inbox rules forwarding payment mail to one external address, three users.",
    trap: false,
  },
  {
    id: "encoded_powershell",
    number: 4,
    gloss: "Encoded command on a production server: the configuration agent, in its window.",
    trap: false,
  },
  {
    id: "lsass_access",
    number: 5,
    gloss: "LSASS read blocked. The account is on the red team exercise list.",
    trap: false,
  },
  {
    id: "kerberoasting",
    number: 6,
    gloss: "A burst of service ticket requests. It is the credentialed vulnerability scanner.",
    trap: false,
  },
  {
    id: "rmm_block",
    number: 7,
    gloss: "The trap: a signed RMM tool, clean on VirusTotal, blocked by the EDR. It is initial access.",
    trap: true,
  },
  {
    id: "cloud_upload",
    number: 8,
    gloss: "The reverse trap: a leaver uploads to personal storage. It is a photo folder.",
    trap: true,
  },
];

export const SCENARIO_ORDER = SCENARIOS.map((s) => s.id);

export function glossOf(id: string): ScenarioGloss | undefined {
  return SCENARIOS.find((s) => s.id === id);
}
