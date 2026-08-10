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
  ('may@staff.invoice-koperasi.id'),
  ('laznas@staff.invoice-koperasi.id')
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
create table if not exists public.invoice_deletions (
  id text primary key,
  pelanggan text,
  dihapus timestamptz not null default now()
);
alter table public.invoice_deletions enable row level security;
create or replace function private.prevent_deleted_invoice_restore()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if exists (select 1 from public.invoice_deletions d where d.id = new.id) then
    raise exception 'Invoice yang telah dihapus tidak boleh dipulihkan' using errcode = '23505';
  end if;
  return new;
end;
$$;
revoke all on function private.prevent_deleted_invoice_restore() from public, anon, authenticated;
drop trigger if exists prevent_deleted_invoice_restore on public.invoices;
create trigger prevent_deleted_invoice_restore
  before insert or update on public.invoices
  for each row execute function private.prevent_deleted_invoice_restore();

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

drop policy if exists "staf semua penghapusan" on public.invoice_deletions;
create policy "staf semua penghapusan" on public.invoice_deletions
  for all to authenticated
  using ((select private.is_invoice_staff()))
  with check ((select private.is_invoice_staff()));

revoke all on public.invoices, public.pengaturan, public.nomor_counter, public.invoice_deletions from anon;
revoke all on public.invoices, public.pengaturan, public.nomor_counter, public.invoice_deletions from authenticated;
grant select, insert, update, delete on public.invoices to authenticated;
grant select, insert, update on public.pengaturan to authenticated;
grant select, insert, update, delete on public.invoice_deletions to authenticated;

do $$ begin
  alter publication supabase_realtime add table public.invoice_deletions;
exception when duplicate_object then null; when others then null; end $$;

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

create or replace function public.buat_invoice_baru(p_invoice jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id text;
  v_tanggal date;
  v_prefix text;
  v_nomor text;
  v_data jsonb;
  v_existing jsonb;
  v_urut int;
  v_attempt int;
begin
  if not (select private.is_invoice_staff()) then
    raise exception 'Akses ditolak' using errcode = '42501';
  end if;
  if jsonb_typeof(p_invoice) <> 'object' then
    raise exception 'Data invoice tidak valid' using errcode = '22023';
  end if;
  v_id := nullif(trim(p_invoice->>'id'), '');
  if v_id is null then
    raise exception 'ID invoice wajib diisi' using errcode = '22023';
  end if;
  if exists (select 1 from public.invoice_deletions d where d.id=v_id) then
    raise exception 'Invoice ini sudah dihapus' using errcode = '23505';
  end if;
  v_tanggal := nullif(p_invoice->>'tanggal','')::date;
  if v_tanggal is null then
    raise exception 'Tanggal invoice wajib diisi' using errcode = '22023';
  end if;
  v_prefix := 'INV/KMS/' || to_char(v_tanggal,'YYYY/MM');

  for v_attempt in 1..100 loop
    insert into public.nomor_counter(prefix,terakhir)
    values(v_prefix,1)
    on conflict(prefix) do update
      set terakhir=public.nomor_counter.terakhir+1
    returning terakhir into v_urut;

    v_nomor := v_prefix || '/' || lpad(v_urut::text,3,'0');
    v_data := jsonb_set(p_invoice,'{no}',to_jsonb(v_nomor),true);
    v_data := jsonb_set(v_data,'{diubah}',to_jsonb(now()),true);

    begin
      insert into public.invoices(id,no,tanggal,pelanggan,total,data,diubah)
      values(
        v_id,
        v_nomor,
        v_tanggal,
        coalesce(v_data->>'pelanggan',''),
        coalesce(nullif(v_data->>'total','')::bigint,0),
        v_data,
        (v_data->>'diubah')::timestamptz
      );
      return v_data;
    exception when unique_violation then
      select i.data into v_existing from public.invoices i where i.id=v_id;
      if found then return v_existing; end if;
    end;
  end loop;

  raise exception 'Nomor invoice tidak dapat dialokasikan' using errcode = '40001';
end;
$$;
revoke all on function public.buat_invoice_baru(jsonb) from public, anon, authenticated;
grant execute on function public.buat_invoice_baru(jsonb) to authenticated;

commit;

-- Setelah Run:
-- 1. Buat ketiga user internal di Authentication > Users > Add user.
-- 2. Jalankan Security Advisor dan uji login dari aplikasi.
-- 3. Tambah staf berikutnya melalui akun Auth admin dan allowlist ini.

-- ================================================================
-- Workflow invoice: Draft -> Diterbitkan (terkunci), audit, dan peran
-- ================================================================
begin;

alter table private.staff_emails
  add column if not exists role_name text not null default 'staff';
do $$ begin
  alter table private.staff_emails add constraint staff_role_valid
    check (role_name in ('admin','staff'));
exception when duplicate_object then null; end $$;
update private.staff_emails set role_name='admin'
  where email in ('ajeng@staff.invoice-koperasi.id','laznas@staff.invoice-koperasi.id');
update private.staff_emails set role_name='staff'
  where email in ('nurul@staff.invoice-koperasi.id','may@staff.invoice-koperasi.id');

create or replace function private.current_invoice_role()
returns text language sql stable security definer set search_path=''
as $$
  select s.role_name from private.staff_emails s
  where s.email=lower(coalesce((select auth.jwt())->>'email',''));
$$;
revoke all on function private.current_invoice_role() from public, anon;
grant execute on function private.current_invoice_role() to authenticated;

create or replace function private.is_invoice_admin()
returns boolean language sql stable security definer set search_path=''
as $$ select coalesce(private.current_invoice_role()='admin',false); $$;
revoke all on function private.is_invoice_admin() from public, anon;
grant execute on function private.is_invoice_admin() to authenticated;

alter table public.invoices add column if not exists workflow_status text not null default 'issued';
alter table public.invoices add column if not exists created_by uuid;
alter table public.invoices add column if not exists updated_by uuid;
alter table public.invoices add column if not exists issued_by uuid;
alter table public.invoices add column if not exists issued_at timestamptz;
alter table public.invoices add column if not exists revision_of text;
do $$ begin
  alter table public.invoices add constraint invoice_workflow_status_valid
    check (workflow_status in ('draft','issued'));
exception when duplicate_object then null; end $$;

update public.invoices
set workflow_status='issued',
    issued_at=coalesce(issued_at,diubah,now()),
    data=coalesce(data,'{}'::jsonb) || jsonb_build_object(
      'workflow_status','issued',
      'issued_at',coalesce(issued_at,diubah,now())
    )
where workflow_status is distinct from 'issued'
   or coalesce(data->>'workflow_status','')='';

create table if not exists public.invoice_activity (
  id bigint generated always as identity primary key,
  invoice_id text,
  action text not null,
  actor_id uuid,
  actor_email text,
  actor_name text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists invoice_activity_invoice_created_idx
  on public.invoice_activity(invoice_id,created_at desc);
alter table public.invoice_activity enable row level security;

create or replace function private.log_invoice_activity(
  p_invoice_id text, p_action text, p_details jsonb default '{}'::jsonb
) returns void language plpgsql security definer set search_path=''
as $$
declare v_email text:=lower(coalesce((select auth.jwt())->>'email',''));
begin
  insert into public.invoice_activity(invoice_id,action,actor_id,actor_email,actor_name,details)
  values(p_invoice_id,p_action,(select auth.uid()),v_email,
    initcap(split_part(v_email,'@',1)),coalesce(p_details,'{}'::jsonb));
end; $$;
revoke all on function private.log_invoice_activity(text,text,jsonb) from public, anon, authenticated;

create or replace function public.profil_invoice()
returns jsonb language sql stable security invoker set search_path=''
as $$
  select jsonb_build_object(
    'email',lower(coalesce((select auth.jwt())->>'email','')),
    'nama',initcap(split_part(lower(coalesce((select auth.jwt())->>'email','')),'@',1)),
    'role',private.current_invoice_role()
  );
$$;
revoke all on function public.profil_invoice() from public, anon, authenticated;
grant execute on function public.profil_invoice() to authenticated;

create or replace function public.daftar_staff_invoice()
returns table(email text,nama text,role_name text)
language plpgsql stable security definer set search_path=''
as $$ begin
  if not private.is_invoice_staff() then raise exception 'Akses ditolak' using errcode='42501'; end if;
  return query select s.email,initcap(split_part(s.email,'@',1)),s.role_name
    from private.staff_emails s order by s.email;
end; $$;
revoke all on function public.daftar_staff_invoice() from public, anon, authenticated;
grant execute on function public.daftar_staff_invoice() to authenticated;

create or replace function public.kelola_peran_staff(p_email text,p_role text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_email text:=lower(trim(p_email)); v_lama text;
begin
  if not private.is_invoice_admin() then raise exception 'Hanya Admin yang dapat mengubah peran' using errcode='42501'; end if;
  if p_role not in ('admin','staff') then raise exception 'Peran tidak valid' using errcode='22023'; end if;
  select role_name into v_lama from private.staff_emails where email=v_email for update;
  if not found then raise exception 'Staf tidak ditemukan' using errcode='P0002'; end if;
  if v_lama='admin' and p_role='staff' and
     (select count(*) from private.staff_emails where role_name='admin')<=1 then
    raise exception 'Minimal satu Admin harus tetap aktif' using errcode='23514';
  end if;
  update private.staff_emails set role_name=p_role where email=v_email;
  perform private.log_invoice_activity(null,'role_changed',jsonb_build_object('email',v_email,'from',v_lama,'to',p_role));
  return jsonb_build_object('email',v_email,'role',p_role);
end; $$;
revoke all on function public.kelola_peran_staff(text,text) from public, anon, authenticated;
grant execute on function public.kelola_peran_staff(text,text) to authenticated;

create or replace function public.simpan_draft(p_invoice jsonb)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_id text; v_data jsonb; v_old public.invoices%rowtype; v_now timestamptz:=now();
begin
  if not private.is_invoice_staff() then raise exception 'Akses ditolak' using errcode='42501'; end if;
  if jsonb_typeof(p_invoice)<>'object' then raise exception 'Data invoice tidak valid' using errcode='22023'; end if;
  v_id:=nullif(trim(p_invoice->>'id'),'');
  if v_id is null then raise exception 'ID draft wajib diisi' using errcode='22023'; end if;
  if exists(select 1 from public.invoice_deletions where id=v_id) then raise exception 'Invoice sudah dihapus' using errcode='23505'; end if;
  select * into v_old from public.invoices where id=v_id for update;
  if found and v_old.workflow_status='issued' then raise exception 'Invoice sudah diterbitkan dan terkunci' using errcode='55000'; end if;
  v_data:=p_invoice || jsonb_build_object('no','','workflow_status','draft','diubah',v_now);
  if found then
    v_data:=v_data || jsonb_build_object('dibuat',coalesce(v_old.data->>'dibuat',p_invoice->>'dibuat',v_now::text));
    update public.invoices set no=null,tanggal=nullif(v_data->>'tanggal','')::date,
      pelanggan=coalesce(v_data->>'pelanggan',''),total=coalesce(nullif(v_data->>'total','')::bigint,0),
      data=v_data,diubah=v_now,updated_by=(select auth.uid()),workflow_status='draft',
      revision_of=nullif(v_data->>'revision_of','') where id=v_id;
    perform private.log_invoice_activity(v_id,'draft_updated','{}'::jsonb);
  else
    v_data:=v_data || jsonb_build_object('dibuat',coalesce(p_invoice->>'dibuat',v_now::text));
    insert into public.invoices(id,no,tanggal,pelanggan,total,data,diubah,workflow_status,created_by,updated_by,revision_of)
    values(v_id,null,nullif(v_data->>'tanggal','')::date,coalesce(v_data->>'pelanggan',''),
      coalesce(nullif(v_data->>'total','')::bigint,0),v_data,v_now,'draft',(select auth.uid()),(select auth.uid()),nullif(v_data->>'revision_of',''));
    perform private.log_invoice_activity(v_id,'draft_created',jsonb_build_object('revision_of',nullif(v_data->>'revision_of','')));
  end if;
  return v_data;
end; $$;
revoke all on function public.simpan_draft(jsonb) from public, anon, authenticated;
grant execute on function public.simpan_draft(jsonb) to authenticated;

create or replace function public.terbitkan_invoice(p_invoice jsonb)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_id text; v_tanggal date; v_prefix text; v_nomor text; v_data jsonb;
  v_old public.invoices%rowtype; v_urut int; v_attempt int; v_now timestamptz:=now();
begin
  if not private.is_invoice_staff() then raise exception 'Akses ditolak' using errcode='42501'; end if;
  if jsonb_typeof(p_invoice)<>'object' then raise exception 'Data invoice tidak valid' using errcode='22023'; end if;
  v_id:=nullif(trim(p_invoice->>'id'),'');
  if v_id is null then raise exception 'ID invoice wajib diisi' using errcode='22023'; end if;
  if jsonb_array_length(coalesce(p_invoice->'items','[]'::jsonb))=0 then raise exception 'Invoice belum memiliki barang' using errcode='22023'; end if;
  if exists(select 1 from public.invoice_deletions where id=v_id) then raise exception 'Invoice sudah dihapus' using errcode='23505'; end if;
  select * into v_old from public.invoices where id=v_id for update;
  if found and v_old.workflow_status='issued' then return v_old.data; end if;
  v_tanggal:=nullif(p_invoice->>'tanggal','')::date;
  if v_tanggal is null then raise exception 'Tanggal wajib diisi' using errcode='22023'; end if;
  v_prefix:='INV/KMS/'||to_char(v_tanggal,'YYYY/MM');
  for v_attempt in 1..100 loop
    insert into public.nomor_counter(prefix,terakhir) values(v_prefix,1)
    on conflict(prefix) do update set terakhir=public.nomor_counter.terakhir+1 returning terakhir into v_urut;
    v_nomor:=v_prefix||'/'||lpad(v_urut::text,3,'0');
    v_data:=p_invoice || jsonb_build_object('no',v_nomor,'workflow_status','issued','issued_at',v_now,
      'issued_by',(select auth.uid()),'diubah',v_now,
      'dibuat',coalesce(v_old.data->>'dibuat',p_invoice->>'dibuat',v_now::text));
    begin
      if v_old.id is not null then
        update public.invoices set no=v_nomor,tanggal=v_tanggal,pelanggan=coalesce(v_data->>'pelanggan',''),
          total=coalesce(nullif(v_data->>'total','')::bigint,0),data=v_data,diubah=v_now,
          workflow_status='issued',updated_by=(select auth.uid()),issued_by=(select auth.uid()),issued_at=v_now,
          revision_of=nullif(v_data->>'revision_of','') where id=v_id;
      else
        insert into public.invoices(id,no,tanggal,pelanggan,total,data,diubah,workflow_status,created_by,updated_by,issued_by,issued_at,revision_of)
        values(v_id,v_nomor,v_tanggal,coalesce(v_data->>'pelanggan',''),coalesce(nullif(v_data->>'total','')::bigint,0),
          v_data,v_now,'issued',(select auth.uid()),(select auth.uid()),(select auth.uid()),v_now,nullif(v_data->>'revision_of',''));
      end if;
      perform private.log_invoice_activity(v_id,'issued',jsonb_build_object('no',v_nomor,'revision_of',nullif(v_data->>'revision_of','')));
      return v_data;
    exception when unique_violation then null;
    end;
  end loop;
  raise exception 'Nomor invoice tidak dapat dialokasikan' using errcode='40001';
end; $$;
revoke all on function public.terbitkan_invoice(jsonb) from public, anon, authenticated;
grant execute on function public.terbitkan_invoice(jsonb) to authenticated;

create or replace function public.buat_invoice_baru(p_invoice jsonb)
returns jsonb language sql security definer set search_path=''
as $$ select public.terbitkan_invoice(p_invoice); $$;
revoke all on function public.buat_invoice_baru(jsonb) from public, anon, authenticated;
grant execute on function public.buat_invoice_baru(jsonb) to authenticated;

create or replace function public.ubah_status_invoice(p_id text,p_status text)
returns jsonb language plpgsql security definer set search_path=''
as $$ declare v_data jsonb; v_lama text;
begin
  if not private.is_invoice_staff() then raise exception 'Akses ditolak' using errcode='42501'; end if;
  if p_status not in ('Belum','Sebagian','Lunas') then raise exception 'Status tidak valid' using errcode='22023'; end if;
  select data->>'status' into v_lama from public.invoices where id=p_id for update;
  if not found then raise exception 'Invoice tidak ditemukan' using errcode='P0002'; end if;
  update public.invoices set data=data||jsonb_build_object('status',p_status,'diubah',now()),
    diubah=now(),updated_by=(select auth.uid()) where id=p_id returning data into v_data;
  perform private.log_invoice_activity(p_id,'payment_status_changed',jsonb_build_object('from',coalesce(v_lama,'Belum'),'to',p_status));
  return v_data;
end; $$;
revoke all on function public.ubah_status_invoice(text,text) from public, anon, authenticated;
grant execute on function public.ubah_status_invoice(text,text) to authenticated;

create or replace function public.hapus_invoice(p_id text)
returns boolean language plpgsql security definer set search_path=''
as $$ declare v_pelanggan text; v_no text;
begin
  if not private.is_invoice_admin() then raise exception 'Hanya Admin yang dapat menghapus invoice' using errcode='42501'; end if;
  select pelanggan,no into v_pelanggan,v_no from public.invoices where id=p_id for update;
  if not found then return false; end if;
  insert into public.invoice_deletions(id,pelanggan) values(p_id,v_pelanggan)
    on conflict(id) do update set pelanggan=excluded.pelanggan,dihapus=now();
  delete from public.invoices where id=p_id;
  perform private.log_invoice_activity(p_id,'deleted',jsonb_build_object('no',v_no,'pelanggan',v_pelanggan));
  return true;
end; $$;
revoke all on function public.hapus_invoice(text) from public, anon, authenticated;
grant execute on function public.hapus_invoice(text) to authenticated;

drop policy if exists "staf semua invoices" on public.invoices;
drop policy if exists "staf baca invoices" on public.invoices;
drop policy if exists "staf tambah invoices" on public.invoices;
drop policy if exists "staf ubah invoices" on public.invoices;
drop policy if exists "staf hapus invoices" on public.invoices;
create policy "staf baca invoices" on public.invoices for select to authenticated
  using ((select private.is_invoice_staff()));
create policy "staf tambah draft" on public.invoices for insert to authenticated
  with check ((select private.is_invoice_staff()) and workflow_status='draft' and created_by=(select auth.uid()));
create policy "staf ubah draft" on public.invoices for update to authenticated
  using ((select private.is_invoice_staff()) and workflow_status='draft')
  with check ((select private.is_invoice_staff()) and workflow_status='draft');
create policy "admin hapus invoices" on public.invoices for delete to authenticated
  using ((select private.is_invoice_admin()));

drop policy if exists "staf semua pengaturan" on public.pengaturan;
drop policy if exists "staf tambah pengaturan" on public.pengaturan;
drop policy if exists "staf ubah pengaturan" on public.pengaturan;
create policy "admin tambah pengaturan" on public.pengaturan for insert to authenticated
  with check ((select private.is_invoice_admin()));
create policy "admin ubah pengaturan" on public.pengaturan for update to authenticated
  using ((select private.is_invoice_admin())) with check ((select private.is_invoice_admin()));

drop policy if exists "staf semua penghapusan" on public.invoice_deletions;
drop policy if exists "admin kelola penghapusan" on public.invoice_deletions;
create policy "staf baca penghapusan" on public.invoice_deletions for select to authenticated
  using ((select private.is_invoice_staff()));
create policy "admin tambah penghapusan" on public.invoice_deletions for insert to authenticated
  with check ((select private.is_invoice_admin()));
create policy "admin ubah penghapusan" on public.invoice_deletions for update to authenticated
  using ((select private.is_invoice_admin())) with check ((select private.is_invoice_admin()));
create policy "admin hapus penghapusan" on public.invoice_deletions for delete to authenticated
  using ((select private.is_invoice_admin()));

drop policy if exists "staf baca aktivitas" on public.invoice_activity;
create policy "staf baca aktivitas" on public.invoice_activity for select to authenticated
  using ((select private.is_invoice_staff()));

revoke all on public.invoice_activity from public,anon,authenticated;
grant select on public.invoice_activity to authenticated;
grant select,insert,update,delete on public.invoices to authenticated;
grant select,insert,update on public.pengaturan to authenticated;
grant select,insert,update,delete on public.invoice_deletions to authenticated;
revoke execute on function public.ambil_nomor(text) from authenticated;
revoke execute on function public.buat_invoice_baru(jsonb) from authenticated;

-- HARGA PASAR RESMI PER DOMISILI DAPUR
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
  constraint market_prices_dapur_check check (dapur in ('SPPG CITEUREUP','SPPG JATIWARNA','SPPG CIMANGGIS')),
  constraint market_prices_region_level_check check (region_level in ('kabupaten','kota')),
  constraint market_prices_price_check check (price > 0),
  constraint market_prices_unit_check check (unit in ('kg','liter')),
  constraint market_prices_source_item_unique unique (dapur,price_date,source_name,commodity_name)
);
create index if not exists market_prices_item_date_idx on public.market_prices(commodity_key,price_date desc);
create index if not exists market_prices_dapur_item_date_idx on public.market_prices(dapur,commodity_key,price_date desc);
alter table public.market_prices enable row level security;
drop policy if exists "staf baca harga pasar" on public.market_prices;
create policy "staf baca harga pasar" on public.market_prices for select to authenticated
  using ((select private.is_invoice_staff()));
revoke all on public.market_prices from public,anon,authenticated;
grant select on public.market_prices to authenticated;

commit;
