-- Ubah username staf Nurul menjadi Nana tanpa mengubah ID atau kata sandi.
do $$
declare
  old_email constant text := 'nurul@staff.invoice-koperasi.id';
  new_email constant text := 'nana@staff.invoice-koperasi.id';
  staff_user_id uuid;
  staff_role text;
  staff_created_at timestamptz;
begin
  select id
    into staff_user_id
    from auth.users
   where lower(email) = old_email
   for update;

  if staff_user_id is null then
    if exists (select 1 from auth.users where lower(email) = new_email) then
      return;
    end if;
    raise exception 'Akun Nurul tidak ditemukan';
  end if;

  if exists (
    select 1 from auth.users
     where lower(email) = new_email
       and id <> staff_user_id
  ) then
    raise exception 'Username Nana sudah digunakan akun lain';
  end if;

  select role_name, dibuat
    into staff_role, staff_created_at
    from private.staff_emails
   where email = old_email;

  insert into private.staff_emails (email, role_name, dibuat)
  values (new_email, coalesce(staff_role, 'staff'), coalesce(staff_created_at, now()))
  on conflict (email) do update
    set role_name = excluded.role_name;

  update auth.users
     set email = new_email,
         raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb)
           || jsonb_build_object('display_name', 'Nana'),
         updated_at = now()
   where id = staff_user_id;

  update auth.identities
     set identity_data = jsonb_set(
           coalesce(identity_data, '{}'::jsonb),
           '{email}',
           to_jsonb(new_email),
           true
         ),
         updated_at = now()
   where user_id = staff_user_id
     and provider = 'email';

  delete from private.staff_emails where email = old_email;
end $$;
