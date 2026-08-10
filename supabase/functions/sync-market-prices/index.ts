import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type MarketPrice = {
  price_date: string;
  dapur: string;
  region_name: string;
  region_level: "kabupaten" | "kota";
  source_name: string;
  source_url: string;
  commodity_key: string;
  commodity_name: string;
  unit: "kg" | "liter";
  price: number;
  fetched_at: string;
};

const BI_SOURCE = "PIHPS Bank Indonesia";
const BI_URL = "https://www.bi.go.id/hargapangan/TabelHarga/PasarTradisionalDaerah";
const BI_API = "https://www.bi.go.id/hargapangan/WebSite/TabelHarga/GetGridDataDaerah";
const BOGOR_SOURCE = "DISDAGIN Kabupaten Bogor / DIRGA";
const BOGOR_URL = "https://disdagin.bogorkab.go.id/fetchharga";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function normalized(value: string) {
  return value.toLocaleLowerCase("id-ID")
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function commodityKey(name: string): string | null {
  const value = normalized(name).replace(/\bcabe\b/g, "cabai");
  if (/^beras kualitas bawah/.test(value)) return "beras_bawah";
  if (/^beras kualitas medium|^beras medium/.test(value)) return "beras_medium";
  if (/^beras kualitas super|^beras premium/.test(value)) return "beras_premium";
  if (/daging ayam ras|daging ayam broiler/.test(value)) return "daging_ayam";
  if (/^daging sapi/.test(value)) return "daging_sapi";
  if (/telur ayam (ras segar|broiler)/.test(value)) return "telur_ayam";
  if (/^bawang merah/.test(value)) return "bawang_merah";
  if (/^bawang putih/.test(value) && !/cutting/.test(value)) return "bawang_putih";
  if (/cabai merah keriting/.test(value)) return "cabai_merah_keriting";
  if (/^cabai merah/.test(value)) return "cabai_merah";
  if (/cabai rawit hijau/.test(value)) return "cabai_rawit_hijau";
  if (/cabai rawit merah/.test(value)) return "cabai_rawit_merah";
  if (/minyak goreng.*curah/.test(value)) return "minyak_goreng_curah";
  if (/minyak goreng.*kemasan/.test(value)) return "minyak_goreng_kemasan";
  if (/gula pasir.*premium|gula pasir.*kemasan/.test(value)) return "gula_pasir_premium";
  if (/gula pasir.*lokal/.test(value)) return "gula_pasir_lokal";
  if (/^garam$/.test(value)) return "garam";
  if (/^ikan lele$/.test(value)) return "ikan_lele";
  if (/^ikan nila$/.test(value)) return "ikan_nila";
  if (/^ikan kembung$|ikan segar kembung/.test(value)) return "ikan_kembung";
  if (/^jagung manis$/.test(value)) return "jagung_manis";
  if (/^kacang hijau$/.test(value)) return "kacang_hijau";
  if (/^kacang tanah$/.test(value)) return "kacang_tanah";
  if (/^kacang panjang$/.test(value)) return "kacang_panjang";
  if (/^kangkung$/.test(value)) return "kangkung";
  if (/^kentang/.test(value)) return "kentang";
  if (/^ketimun/.test(value)) return "ketimun";
  if (/^kol|^kubis/.test(value)) return "kol";
  if (/^tahu/.test(value)) return "tahu";
  if (/^tempe/.test(value)) return "tempe";
  if (/tepung terigu/.test(value)) return "tepung_terigu";
  if (/^tomat merah$/.test(value)) return "tomat";
  return null;
}

function jakartaDate(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Jakarta",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function addDays(iso: string, days: number) {
  const date = new Date(`${iso}T12:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function parseBiDate(value: string) {
  const [day, month, year] = value.split("/");
  return `${year}-${month}-${day}`;
}

function parsePrice(value: unknown) {
  const number = Number(String(value ?? "").replace(/,/g, ""));
  return Number.isFinite(number) && number > 0 ? Math.round(number) : null;
}

async function fetchJson(url: string, timeoutMs = 15_000) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "invoice-koperasi-market-price-sync/1.0",
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return await response.json();
}

async function fetchBiPrices(
  dapur: string,
  regionName: string,
  regencyId: number,
  today: string,
  fetchedAt: string,
) {
  const query = new URLSearchParams({
    price_type_id: "1",
    comcat_id: "",
    province_id: "12",
    regency_id: String(regencyId),
    market_id: "",
    tipe_laporan: "1",
    start_date: addDays(today, -8),
    end_date: today,
  });
  const payload = await fetchJson(`${BI_API}?${query}`);
  const result: MarketPrice[] = [];
  for (const row of payload?.data ?? []) {
    if (Number(row.level) !== 2) continue;
    const key = commodityKey(String(row.name ?? ""));
    if (!key) continue;
    const dateKeys = Object.keys(row)
      .filter((item) => /^\d{2}\/\d{2}\/\d{4}$/.test(item) && parsePrice(row[item]))
      .sort((a, b) => parseBiDate(b).localeCompare(parseBiDate(a)));
    if (!dateKeys.length) continue;
    const price = parsePrice(row[dateKeys[0]]);
    if (!price) continue;
    result.push({
      price_date: parseBiDate(dateKeys[0]),
      dapur,
      region_name: regionName,
      region_level: "kota",
      source_name: BI_SOURCE,
      source_url: BI_URL,
      commodity_key: key,
      commodity_name: String(row.name).trim(),
      unit: /minyak goreng/i.test(String(row.name)) ? "liter" : "kg",
      price,
      fetched_at: fetchedAt,
    });
  }
  return result;
}

async function fetchBogorPrices(fetchedAt: string) {
  const payload = await fetchJson(BOGOR_URL, 8_000);
  const priceDate = String(payload?.data?.price_date ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(priceDate)) throw new Error("Tanggal sumber Bogor tidak valid");
  const result: MarketPrice[] = [];
  for (const item of payload?.data?.price ?? []) {
    const name = String(item.comodity ?? "").trim();
    const key = commodityKey(name);
    const price = parsePrice(item.price);
    if (!key || !price) continue;
    result.push({
      price_date: priceDate,
      dapur: "SPPG CITEUREUP",
      region_name: "Kabupaten Bogor (acuan Citeureup)",
      region_level: "kabupaten",
      source_name: BOGOR_SOURCE,
      source_url: BOGOR_URL,
      commodity_key: key,
      commodity_name: name,
      unit: /minyak goreng/i.test(name) ? "liter" : "kg",
      price,
      fetched_at: fetchedAt,
    });
  }
  return result;
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "Metode tidak diizinkan" }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const authorization = request.headers.get("Authorization") ?? "";
  if (!supabaseUrl || !anonKey || !serviceRoleKey || !authorization) {
    return json({ error: "Konfigurasi otorisasi tidak lengkap" }, 401);
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false },
  });
  const { data: allowed, error: accessError } = await userClient.rpc("cek_akses_invoice");
  if (accessError || allowed !== true) return json({ error: "Akses staf ditolak" }, 403);

  const fetchedAt = new Date().toISOString();
  const today = jakartaDate();
  const jobs = await Promise.allSettled([
    fetchBogorPrices(fetchedAt),
    fetchBiPrices(
      "SPPG JATIWARNA",
      "Kota Bekasi (acuan Pondok Melati/Jatiwarna)",
      30,
      today,
      fetchedAt,
    ),
    fetchBiPrices(
      "SPPG CIMANGGIS",
      "Kota Depok (acuan Cimanggis)",
      32,
      today,
      fetchedAt,
    ),
  ]);

  const rows = jobs.flatMap((job) => job.status === "fulfilled" ? job.value : []);
  const warnings = jobs.flatMap((job, index) => job.status === "rejected"
    ? [`${["Kabupaten Bogor", "Kota Bekasi", "Kota Depok"][index]}: ${job.reason?.message ?? job.reason}`]
    : []);
  if (warnings.length) console.warn("Sinkronisasi harga parsial", warnings);
  if (!rows.length) return json({ error: "Semua sumber harga gagal diambil", warnings }, 502);

  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
  const { error: upsertError } = await admin.from("market_prices").upsert(rows, {
    onConflict: "dapur,price_date,source_name,commodity_name",
  });
  if (upsertError) return json({ error: upsertError.message, warnings }, 500);

  return json({ ok: true, date: today, saved: rows.length, warnings });
});
