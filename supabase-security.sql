-- Hardening keamanan Sistem Invoice Koperasi Mitra Sanur
-- Aditif dan idempotent: tidak menghapus invoice atau pengaturan.
-- Akun Auth dibuat oleh admin; pendaftaran publik harus dinonaktifkan.

begin;

create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create table if not exists private.staff_emails (
  email text primary key,
  dibuat timestamptz not null default now(),
  constraint staff_email_lowercase check (email = lower(email)),
  constraint staff_email_format check (position('@' in email) > 1)
);
revoke all on private.staff_emails from public, anon, authenticated;

insert into private.staff_emails (email) values
  ('ajeng@staff.invoice-koperasi.id'),
  ('nurul@staff.invoice-koperasi.id'),
  ('may@staff.invoice-koperasi.id')
on conflict (email) do nothing;

-- Blokir pendaftaran Auth untuk alamat di luar allowlist, termasuk bila
-- pengaturan "Allow new users to sign up" tidak sengaja diaktifkan kembali.
create or replace function private.enforce_invoice_staff_signup()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.email is null or not exists (
    select 1 from private.staff_emails s where s.email = lower(new.email)
  ) then
    raise exception 'Pendaftaran akun tidak diizinkan' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function private.enforce_invoice_staff_signup() from public, anon, authenticated;
drop trigger if exists enforce_invoice_staff_signup on auth.users;
create trigger enforce_invoice_staff_signup
  before insert on auth.users
  for each row execute function private.enforce_invoice_staff_signup();

create or replace function private.is_invoice_staff()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null
    and exists (
      select 1
      from private.staff_emails s
      where s.email = lower(coalesce((select auth.jwt()) ->> 'email', ''))
    );
$$;
revoke all on function private.is_invoice_staff() from public, anon;
grant execute on function private.is_invoice_staff() to authenticated;

create or replace function public.cek_akses_invoice()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$ select private.is_invoice_staff(); $$;
revoke all on function public.cek_akses_invoice() from public, anon, authenticated;
grant execute on function public.cek_akses_invoice() to authenticated;

alter table public.invoices enable row level security;
alter table public.pengaturan enable row level security;
alter table public.nomor_counter enable row level security;

drop policy if exists "anon semua invoices" on public.invoices;
drop policy if exists "anon semua pengaturan" on public.pengaturan;
drop policy if exists "anon semua counter" on public.nomor_counter;

drop policy if exists "staf baca invoices" on public.invoices;
drop policy if exists "staf tambah invoices" on public.invoices;
drop policy if exists "staf ubah invoices" on public.invoices;
drop policy if exists "staf hapus invoices" on public.invoices;
create policy "staf baca invoices" on public.invoices
  for select to authenticated using ((select private.is_invoice_staff()));
create policy "staf tambah invoices" on public.invoices
  for insert to authenticated with check ((select private.is_invoice_staff()));
create policy "staf ubah invoices" on public.invoices
  for update to authenticated
  using ((select private.is_invoice_staff()))
  with check ((select private.is_invoice_staff()));
create policy "staf hapus invoices" on public.invoices
  for delete to authenticated using ((select private.is_invoice_staff()));

drop policy if exists "staf baca pengaturan" on public.pengaturan;
drop policy if exists "staf tambah pengaturan" on public.pengaturan;
drop policy if exists "staf ubah pengaturan" on public.pengaturan;
create policy "staf baca pengaturan" on public.pengaturan
  for select to authenticated using ((select private.is_invoice_staff()));
create policy "staf tambah pengaturan" on public.pengaturan
  for insert to authenticated with check ((select private.is_invoice_staff()));
create policy "staf ubah pengaturan" on public.pengaturan
  for update to authenticated
  using ((select private.is_invoice_staff()))
  with check ((select private.is_invoice_staff()));

revoke all on public.invoices, public.pengaturan, public.nomor_counter from anon;
revoke all on public.invoices, public.pengaturan, public.nomor_counter from authenticated;
grant select, insert, update, delete on public.invoices to authenticated;
grant select, insert, update on public.pengaturan to authenticated;

create or replace function public.ambil_nomor(p_prefix text)
returns int
language plpgsql
security definer
set search_path = ''
as $$
declare n int;
begin
  if not (select private.is_invoice_staff()) then
    raise exception 'Akses ditolak' using errcode = '42501';
  end if;
  if p_prefix !~ '^INV/KMS/[0-9]{4}/(0[1-9]|1[0-2])$' then
    raise exception 'Prefix invoice tidak valid' using errcode = '22023';
  end if;
  insert into public.nomor_counter (prefix, terakhir)
  values (p_prefix, 1)
  on conflict (prefix) do update
    set terakhir = public.nomor_counter.terakhir + 1
  returning terakhir into n;
  return n;
end;
$$;
revoke all on function public.ambil_nomor(text) from public, anon, authenticated;
grant execute on function public.ambil_nomor(text) to authenticated;

commit;

-- Setelah Run:
-- 1. Buat ketiga user internal di Authentication > Users > Add user.
-- 2. Jalankan Security Advisor dan uji login dari aplikasi.
-- 3. Tambah staf berikutnya melalui akun Auth admin dan allowlist ini.
