import { secureReadFile } from "./dist/index.js";

const paths = [".env", "hello.txt", "secrets/data.txt", "../package.json"];

for (const p of paths) {
  try {
    const result = await secureReadFile(p);
    console.log("ALLOWED:", p, result);
  } catch (err) {
    console.log("BLOCKED:", p, err.constructor.name);
  }
}
