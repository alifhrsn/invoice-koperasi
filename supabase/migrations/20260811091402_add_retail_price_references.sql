-- Referensi retail/marketplace terpisah dari harga pasar resmi.
create table if not exists public.retail_price_references (
  id bigint generated always as identity primary key,
  item_key text not null,
  item_name text not null,
  brand text,
  package_label text not null,
  comparison_quantity numeric(12,3) not null,
  comparison_unit text not null,
  price numeric(14,2) not null,
  price_per_unit numeric(14,2) generated always as (round(price / comparison_quantity, 2)) stored,
  source_name text not null,
  source_url text not null,
  seller_name text,
  seller_location text,
  checked_at timestamptz not null,
  notes text,
  constraint retail_price_references_price_check check (price > 0),
  constraint retail_price_references_quantity_check check (comparison_quantity > 0),
  constraint retail_price_references_source_unique unique (item_key, package_label, source_name, source_url)
);

create index if not exists retail_price_references_item_checked_idx
  on public.retail_price_references (item_key, checked_at desc);

alter table public.retail_price_references enable row level security;

drop policy if exists "staf baca referensi retail" on public.retail_price_references;
create policy "staf baca referensi retail"
  on public.retail_price_references
  for select
  to authenticated
  using ((select private.is_invoice_staff()));

revoke all on public.retail_price_references from public, anon, authenticated;
grant select on public.retail_price_references to authenticated;

insert into public.retail_price_references
  (item_key,item_name,brand,package_label,comparison_quantity,comparison_unit,price,source_name,source_url,checked_at,notes)
values
  ('masker-onemed','Masker medis OneMed','OneMed','1 box isi 50 pcs',50,'pcs',29999,'Shopee','https://shopee.co.id/Onemed-Masker-isi-50-Pcs-Box-i.173363033.24818975682','2026-08-11 10:00:00+07','Harga listing publik; warna, tipe masker, promo, dan ongkir perlu diperiksa kembali.'),
  ('tali-rafia-1kg','Tali rafia','Tanpa merek','1 roll berat 1 kg',1,'kg',22000,'Blibli','https://www.blibli.com/jual/tali-rafia-hitam-1-kg','2026-08-11 10:00:00+07','Referensi listing tali rafia hitam 1 kg; warna, berat bersih, penjual, dan ongkir perlu diperiksa kembali.'),
  ('sabun-ekonomi-780ml-dus','Sabun cuci piring Ekonomi','Ekonomi','1 dus isi 12 pouch x 780 ml',12,'pouch',115000,'Blibli','https://www.blibli.com/jual/sabun-cuci-piring-ekonomi-ekonomi-1-dus','2026-08-11 10:00:00+07','Harga listing publik untuk dus isi 12 pouch; pastikan ukuran 780 ml, varian, promo, dan ongkir sebelum membeli.')
on conflict (item_key,package_label,source_name,source_url) do update set
  item_name=excluded.item_name,
  brand=excluded.brand,
  comparison_quantity=excluded.comparison_quantity,
  comparison_unit=excluded.comparison_unit,
  price=excluded.price,
  checked_at=excluded.checked_at,
  notes=excluded.notes;
