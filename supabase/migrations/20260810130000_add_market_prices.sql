create table if not exists public.market_prices (
  id bigint generated always as identity primary key,
  price_date date not null,
  dapur text not null,
  region_name text not null,
  region_level text not null,
  source_name text not null,
  source_url text not null,
  commodity_key text not null,
  commodity_name text not null,
  unit text not null default 'kg',
  price numeric(14,2) not null,
  fetched_at timestamptz not null default now(),
  constraint market_prices_dapur_check check (
    dapur in ('SPPG CITEUREUP', 'SPPG JATIWARNA', 'SPPG CIMANGGIS')
  ),
  constraint market_prices_region_level_check check (
    region_level in ('kabupaten', 'kota')
  ),
  constraint market_prices_price_check check (price > 0),
  constraint market_prices_unit_check check (unit in ('kg', 'liter')),
  constraint market_prices_source_item_unique unique (
    dapur, price_date, source_name, commodity_name
  )
);

create index if not exists market_prices_item_date_idx
  on public.market_prices (commodity_key, price_date desc);

create index if not exists market_prices_dapur_item_date_idx
  on public.market_prices (dapur, commodity_key, price_date desc);

alter table public.market_prices enable row level security;

drop policy if exists "staf baca harga pasar" on public.market_prices;
create policy "staf baca harga pasar"
  on public.market_prices
  for select
  to authenticated
  using ((select private.is_invoice_staff()));

revoke all on public.market_prices from public, anon, authenticated;
grant select on public.market_prices to authenticated;

