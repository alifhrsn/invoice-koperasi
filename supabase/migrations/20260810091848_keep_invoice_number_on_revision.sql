create or replace function public.terbitkan_invoice(p_invoice jsonb)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_id text; v_revision_id text; v_tanggal date; v_prefix text; v_nomor text; v_data jsonb;
  v_old public.invoices%rowtype; v_source public.invoices%rowtype;
  v_urut int; v_attempt int; v_now timestamptz:=now();
begin
  if not private.is_invoice_staff() then raise exception 'Akses ditolak' using errcode='42501'; end if;
  if jsonb_typeof(p_invoice)<>'object' then raise exception 'Data invoice tidak valid' using errcode='22023'; end if;
  v_id:=nullif(trim(p_invoice->>'id'),'');
  v_revision_id:=nullif(trim(p_invoice->>'revision_of'),'');
  if v_id is null then raise exception 'ID invoice wajib diisi' using errcode='22023'; end if;
  if jsonb_array_length(coalesce(p_invoice->'items','[]'::jsonb))=0 then raise exception 'Invoice belum memiliki barang' using errcode='22023'; end if;
  if exists(select 1 from public.invoice_deletions where id=v_id) then raise exception 'Invoice sudah dihapus' using errcode='23505'; end if;
  select * into v_old from public.invoices where id=v_id for update;
  v_tanggal:=nullif(p_invoice->>'tanggal','')::date;
  if v_tanggal is null then raise exception 'Tanggal wajib diisi' using errcode='22023'; end if;

  if v_revision_id is not null then
    select * into v_source from public.invoices where id=v_revision_id for update;
    if not found or v_source.workflow_status<>'issued' then
      raise exception 'Invoice asal revisi tidak ditemukan atau belum diterbitkan' using errcode='P0002';
    end if;
    if v_source.no is null then raise exception 'Invoice asal tidak memiliki nomor resmi' using errcode='55000'; end if;
    v_data:=(p_invoice - 'revision_of') || jsonb_build_object(
      'id',v_source.id,'no',v_source.no,'workflow_status','issued',
      'issued_at',coalesce(v_source.issued_at,v_now),'issued_by',v_source.issued_by,
      'dibuat',coalesce(v_source.data->>'dibuat',p_invoice->>'dibuat',v_now::text),
      'diubah',v_now,'revised_at',v_now,'revised_by',(select auth.uid()));
    update public.invoices set tanggal=v_tanggal,pelanggan=coalesce(v_data->>'pelanggan',''),
      total=coalesce(nullif(v_data->>'total','')::bigint,0),data=v_data,diubah=v_now,
      updated_by=(select auth.uid()) where id=v_source.id;
    if v_old.id is not null and v_old.id<>v_source.id and v_old.workflow_status='draft' then
      delete from public.invoices where id=v_old.id;
    end if;
    perform private.log_invoice_activity(v_source.id,'revised',jsonb_build_object('no',v_source.no,'draft_id',v_id));
    return v_data;
  end if;

  if v_old.id is not null and v_old.workflow_status='issued' then return v_old.data; end if;
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
