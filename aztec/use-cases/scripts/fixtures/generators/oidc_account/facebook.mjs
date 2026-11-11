// The facebook account fixture: its audience and subject.
import rs256 from "./rs256.mjs";

export default rs256(
  "facebook",
  "FacebookAccount",
  "synthetic-facebook-app-id",
  "synthetic-pairwise-subject",
);
