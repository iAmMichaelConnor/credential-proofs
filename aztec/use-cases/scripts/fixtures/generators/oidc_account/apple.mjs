// The apple account fixture: its audience and subject.
import rs256 from "./rs256.mjs";

export default rs256(
  "apple",
  "AppleAccount",
  "synthetic-client-id-0123456789abcdefghijklmnopqrstuvwxyz-0123456789",
  "synthetic-user",
);
