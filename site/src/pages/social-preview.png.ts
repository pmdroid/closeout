import sharp from "sharp";
import preview from "../assets/social-preview.svg?raw";

export async function GET() {
  const image = await sharp(Buffer.from(preview)).png().toBuffer();
  return new Response(new Uint8Array(image), {
    headers: { "Content-Type": "image/png" },
  });
}
