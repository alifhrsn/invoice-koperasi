alter table public.market_prices
  add column if not exists market_name text not null default '';

alter table public.market_prices
  drop constraint if exists market_prices_source_item_unique;

alter table public.market_prices
  add constraint market_prices_source_item_unique unique (
    dapur, price_date, source_name, market_name, commodity_name
  );
