const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type":"application/json; charset=utf-8", ...headers }
});
const htmlEscape = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), c=>c.charCodeAt(0));
async function digest(s) { return b64(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:100000,hash:"SHA-256"},key,256);
  return `${salt}.${b64(bits)}`;
}
async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(".");
  if (!salt || !expected) return false;
  const actual = (await passwordHash(password,salt)).split(".")[1];
  return actual === expected;
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return b64(await crypto.subtle.sign("HMAC",key,enc.encode(value)));
}
async function makeSession(user, env) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await digest(token);
  const expires = new Date(Date.now()+7*86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(tokenHash,user.id,expires).run();
  return token;
}
function cookie(request) {
  return (request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("baza_session="))?.slice(13) || null;
}
async function currentUser(request, env) {
  const token = cookie(request);
  if (!token) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.full_name,u.role,u.organization_id
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(tokenHash,new Date().toISOString()).first();
  return row || null;
}
const requireUser = async (req,env) => {
  const user = await currentUser(req,env);
  return user ? {user} : {response:json({error:"Требуется вход в систему"},401)};
};
const adminOnly = user => user.role === "admin";
async function getTaskAccess(env,user,id) {
  const task=await env.DB.prepare("SELECT * FROM tasks WHERE id=?").bind(id).first();
  if(!task) return {error:json({error:"Задание не найдено"},404)};
  if(user.role!=="admin" && task.assigned_to!==user.id && task.created_by!==user.id) return {error:json({error:"Нет доступа к заданию"},403)};
  return {task};
}
async function api(request, env) {
  const url = new URL(request.url), path=url.pathname, method=request.method;
  if (!env.SESSION_SECRET) return json({error:"Не задан SESSION_SECRET в настройках Worker"},500);

  if (path === "/api/admin/recover-password" && method==="POST") {
    const body=await request.json();
    if (!env.SETUP_SECRET || body.setupSecret !== env.SETUP_SECRET) return json({error:"Неверный код восстановления"},403);
    const username=String(body.username||"").trim();
    const password=String(body.password||"");
    if (!username || password.length<12) return json({error:"Укажите логин администратора и новый пароль не короче 12 символов"},400);
    const user=await env.DB.prepare("SELECT id,role FROM users WHERE username=? AND active=1").bind(username).first();
    if (!user || user.role!=="admin") return json({error:"Активный администратор с таким логином не найден"},404);
    const salt=b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash=await passwordHash(password,salt);
    await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(hash,user.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id).run();
    return json({ok:true,message:"Пароль администратора обновлён. Войдите с новым паролем."});
  }

  if (path === "/api/setup" && method==="POST") {
    const body=await request.json();
    if (!env.SETUP_SECRET || body.setupSecret !== env.SETUP_SECRET) return json({error:"Неверный код первоначальной настройки"},403);
    const exists=await env.DB.prepare("SELECT id FROM users LIMIT 1").first();
    if (exists) return json({error:"Первый администратор уже создан"},409);
    if (!body.username || !body.password || body.password.length<12 || !body.fullName) return json({error:"Укажите ФИО, логин и пароль не короче 12 символов"},400);
    const salt=b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash=await passwordHash(body.password,salt);
    const result=await env.DB.prepare("INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,'admin')").bind(body.username,body.fullName,hash).run();
    return json({ok:true,userId:result.meta.last_row_id});
  }

  if (path === "/api/login" && method==="POST") {
    const body=await request.json();
    const user=await env.DB.prepare("SELECT * FROM users WHERE username=? AND active=1").bind(body.username||"").first();
    if (!user || !(await verifyPassword(body.password||"",user.password_hash))) return json({error:"Неверный логин или пароль"},401);
    const token=await makeSession(user,env);
    return json({ok:true,user:{id:user.id,fullName:user.full_name,role:user.role}},200,{
      "Set-Cookie":`baza_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });
  }

  if (path==="/api/logout" && method==="POST") {
    const token=cookie(request);
    if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ok:true},200,{"Set-Cookie":"baza_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"});
  }

  const auth=await requireUser(request,env);
  if(auth.response) return auth.response;
  const user=auth.user;

  if(path==="/api/me" && method==="GET") return json({user});

  if(path==="/api/employees" && method==="GET") {
    const q=(url.searchParams.get("q")||"").trim();
    const slingers=url.searchParams.get("slingers")==="1";
    const state=await env.DB.prepare("SELECT active_batch_id FROM employee_import_state WHERE id=1").first();
    if(!state?.active_batch_id) return json({employees:[],total:0});
    let sql="SELECT e.id,e.employee_name,e.position,e.employer,e.instruction_date,e.form_o86_value,e.form_086_value,e.has_medical_certificate,e.slinger_certificate,e.slinger_expiry_date FROM employees e WHERE e.batch_id=?";
    const args=[state.active_batch_id];
    if(q){sql+=" AND LOWER(e.employee_name) LIKE LOWER(?)";args.push("%"+q+"%");}
    const slingerPosition="LOWER(TRIM(COALESCE(e.position,''))) LIKE '%стропальщик%'";
    if(slingers) sql+=" AND "+slingerPosition;
    else if(!q) sql+=" AND NOT ("+slingerPosition+")";
    sql+=" ORDER BY employee_name LIMIT 1000";
    const rows=await env.DB.prepare(sql).bind(...args).all();
    return json({employees:rows.results,total:rows.results.length});
  }
  if(path==="/api/employees/import" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Только администратор может загружать базу работников"},403);
    const b=await request.json();
    if(!b.batchId || !Array.isArray(b.rows) || b.rows.length>400) return json({error:"Передайте batchId и не более 400 строк за один запрос"},400);
    const statements=[];
    for(const r of b.rows) {
      const name=String(r.employee_name||"").trim();
      const sourceKey=String(r.source_key||"").trim();
      if(!name || !sourceKey) continue;
      statements.push(env.DB.prepare(`INSERT INTO employees(batch_id,source_key,employee_name,position,employer,instruction_date,form_o86_value,form_086_value,has_medical_certificate,slinger_certificate,slinger_expiry_date)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(batch_id,source_key) DO UPDATE SET employee_name=excluded.employee_name,position=excluded.position,employer=excluded.employer,instruction_date=excluded.instruction_date,form_o86_value=excluded.form_o86_value,form_086_value=excluded.form_086_value,has_medical_certificate=excluded.has_medical_certificate,slinger_certificate=excluded.slinger_certificate,slinger_expiry_date=excluded.slinger_expiry_date,updated_at=CURRENT_TIMESTAMP`)
        .bind(String(b.batchId),sourceKey,name,String(r.position||""),String(r.employer||""),r.instruction_date||null,String(r.form_o86_value||""),String(r.form_086_value||""),r.has_medical_certificate?1:0,String(r.slinger_certificate||""),r.slinger_expiry_date||null));
    }
    if(statements.length) await env.DB.batch(statements);
    if(b.publish===true) {
      await env.DB.prepare("UPDATE employee_import_state SET active_batch_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=1").bind(String(b.batchId)).run();
      await env.DB.prepare("DELETE FROM employees WHERE batch_id<>?").bind(String(b.batchId)).run();
    }
    return json({ok:true,saved:statements.length,published:b.publish===true});
  }
  if(path==="/api/employees/slingers/import" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Только администратор может загружать данные стропальщиков"},403);
    const b=await request.json();
    if(!Array.isArray(b.rows) || b.rows.length<1 || b.rows.length>400) return json({error:"Передайте от 1 до 400 записей стропальщиков"},400);
    const state=await env.DB.prepare("SELECT active_batch_id FROM employee_import_state WHERE id=1").first();
    if(!state?.active_batch_id) return json({error:"Сначала загрузите общую базу работников"},400);
    const unique=new Map();
    for(const r of b.rows) {
      const name=String(r.employee_name||"").trim();
      if(!name) continue;
      const expiry=String(r.slinger_expiry_date||"").trim();
      if(expiry && !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) return json({error:"Неверный формат даты окончания у "+name},400);
      unique.set(name.toLowerCase().replace(/\s+/g," "),{name,certificate:String(r.slinger_certificate||"").trim(),expiry:expiry||null});
    }
    const statements=[];
    let updated=0,added=0;
    for(const [key,r] of unique) {
      const existing=await env.DB.prepare("SELECT id FROM employees WHERE batch_id=? AND lower(trim(employee_name))=lower(trim(?)) ORDER BY id LIMIT 1").bind(state.active_batch_id,r.name).first();
      if(existing) {
        statements.push(env.DB.prepare("UPDATE employees SET position='Стропальщик',slinger_certificate=?,slinger_expiry_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(r.certificate||"не указан",r.expiry,existing.id));
        updated++;
      } else {
        const sourceKey="slinger-upload:"+key;
        statements.push(env.DB.prepare(`INSERT INTO employees(batch_id,source_key,employee_name,position,slinger_certificate,slinger_expiry_date)
          VALUES(?,?,?,'Стропальщик',?,?)
          ON CONFLICT(batch_id,source_key) DO UPDATE SET employee_name=excluded.employee_name,slinger_certificate=excluded.slinger_certificate,slinger_expiry_date=excluded.slinger_expiry_date,updated_at=CURRENT_TIMESTAMP`)
          .bind(state.active_batch_id,sourceKey,r.name,r.certificate||"не указан",r.expiry));
        added++;
      }
    }
    if(statements.length) await env.DB.batch(statements);
    return json({ok:true,updated,added,total:unique.size});
  }

  if(path==="/api/certificates" && method==="GET") {
    const rows=await env.DB.prepare("SELECT id,employee_name,position,certificate_number,valid_until,updated_at FROM certificates ORDER BY valid_until,employee_name").all();
    return json({certificates:rows.results});
  }
  if(path==="/api/certificates" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Только администратор может добавлять удостоверения"},403);
    const b=await request.json();
    if(!String(b.employeeName||"").trim() || !/^\d{4}-\d{2}-\d{2}$/.test(b.validUntil||"")) return json({error:"Укажите ФИО и дату окончания"},400);
    const r=await env.DB.prepare("INSERT INTO certificates(employee_name,position,certificate_number,valid_until,updated_by) VALUES(?,?,?,?,?)")
      .bind(String(b.employeeName).trim(),b.position||"",b.certificateNumber||"",b.validUntil,user.id).run();
    return json({ok:true,id:r.meta.last_row_id});
  }
  const certMatch=path.match(/^\/api\/certificates\/(\d+)$/);
  if(certMatch && method==="PATCH") {
    if(!adminOnly(user)) return json({error:"Только администратор может изменять удостоверения"},403);
    const b=await request.json();
    if(!String(b.employeeName||"").trim() || !/^\d{4}-\d{2}-\d{2}$/.test(b.validUntil||"")) return json({error:"Проверьте ФИО и дату окончания"},400);
    const r=await env.DB.prepare("UPDATE certificates SET employee_name=?,position=?,certificate_number=?,valid_until=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(String(b.employeeName).trim(),b.position||"",b.certificateNumber||"",b.validUntil,user.id,Number(certMatch[1])).run();
    if(!r.meta.changes) return json({error:"Удостоверение не найдено"},404);
    return json({ok:true});
  }

  if(path==="/api/users" && method==="GET") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const rows=await env.DB.prepare("SELECT id,username,full_name,role,active FROM users ORDER BY full_name").all();
    return json({users:rows.results});
  }
  if(path==="/api/users" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const b=await request.json();
    if(!b.username||!b.fullName||!b.password||b.password.length<12) return json({error:"Заполните ФИО, логин и пароль от 12 символов"},400);
    const salt=b64(crypto.getRandomValues(new Uint8Array(16))), hash=await passwordHash(b.password,salt);
    try { const r=await env.DB.prepare("INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,?)").bind(b.username,b.fullName,hash,b.role==="admin"?"admin":"engineer").run(); return json({ok:true,id:r.meta.last_row_id}); }
    catch { return json({error:"Логин уже занят"},409); }
  }
  if(path.startsWith("/api/users/") && method==="DELETE") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const id=Number(path.split("/").pop());
    if(!Number.isInteger(id)||id<1) return json({error:"Неверный пользователь"},400);
    if(id===user.id) return json({error:"Нельзя удалить собственную учётную запись"},400);
    const target=await env.DB.prepare("SELECT id,active FROM users WHERE id=?").bind(id).first();
    if(!target) return json({error:"Пользователь не найден"},404);
    await env.DB.prepare("UPDATE users SET active=0 WHERE id=?").bind(id).run();
    return json({ok:true,disabled:true});
  }
  if(path==="/api/tasks" && method==="GET") {
    const rows=await env.DB.prepare(`SELECT t.*,u.full_name assigned_name,c.full_name creator_name,
      (SELECT hu.full_name FROM task_history h JOIN users hu ON hu.id=h.user_id WHERE h.task_id=t.id AND h.new_status='В работе' ORDER BY h.created_at DESC,h.id DESC LIMIT 1) in_progress_by_name,
      (SELECT hu.full_name FROM task_history h JOIN users hu ON hu.id=h.user_id WHERE h.task_id=t.id AND h.new_status='На проверке' ORDER BY h.created_at DESC,h.id DESC LIMIT 1) review_by_name,
      (SELECT hu.full_name FROM task_history h JOIN users hu ON hu.id=h.user_id WHERE h.task_id=t.id AND h.new_status='Выполнено' ORDER BY h.created_at DESC,h.id DESC LIMIT 1) completed_by_name
      FROM tasks t LEFT JOIN users u ON u.id=t.assigned_to JOIN users c ON c.id=t.created_by
      ORDER BY CASE WHEN t.status='Выполнено' THEN 1 ELSE 0 END,t.due_date`).all();
    return json({tasks:rows.results});
  }
  if(path==="/api/tasks" && method==="POST") {
    const b=await request.json();
    if(!b.title?.trim()) return json({error:"Введите название задания"},400);
    const r=await env.DB.prepare("INSERT INTO tasks(title,description,assigned_to,created_by,due_date) VALUES(?,?,?,?,?)")
      .bind(b.title.trim(),b.description||"",b.assignedTo||null,user.id,b.dueDate||null).run();
    return json({ok:true,id:r.meta.last_row_id});
  }
  if(path.startsWith("/api/tasks/") && path.endsWith("/report") && method==="GET") {
    const id=Number(path.split("/")[3]), access=await getTaskAccess(env,user,id);
    if(access.error) return access.error;
    const [photos,videos]=await Promise.all([
      env.DB.prepare("SELECT id,photo_type,content_type,created_at FROM task_photos WHERE task_id=? ORDER BY created_at,id").bind(id).all(),
      env.DB.prepare("SELECT id,content_type,original_name,size_bytes,created_at FROM task_videos WHERE task_id=? ORDER BY created_at,id").bind(id).all()
    ]);
    return json({task:{id:access.task.id,status:access.task.status,completion_comment:access.task.completion_comment||"",submitted_at:access.task.submitted_at||null},photos:photos.results.map(x=>({...x,url:`/api/tasks/${id}/files/photo/${x.id}`})),videos:videos.results.map(x=>({...x,url:`/api/tasks/${id}/files/video/${x.id}`}))});
  }
  if(path.startsWith("/api/tasks/") && path.endsWith("/report") && method==="POST") {
    const id=Number(path.split("/")[3]), access=await getTaskAccess(env,user,id);
    if(access.error) return access.error;
    const form=await request.formData(), comment=String(form.get("comment")||"").trim();
    const before=form.getAll("beforePhotos").filter(x=>x instanceof File && x.size), after=form.getAll("afterPhotos").filter(x=>x instanceof File && x.size), videos=form.getAll("videos").filter(x=>x instanceof File && x.size);
    if(before.length+after.length>8 || videos.length>3) return json({error:"Можно приложить не более 8 фотографий и 3 видео за один отчёт"},400);
    const allPhotos=[...before.map(file=>({file,type:"before"})),...after.map(file=>({file,type:"after"}))];
    if(allPhotos.some(x=>!x.file.type.startsWith("image/") || x.file.size>12*1024*1024)) return json({error:"Фотографии должны быть изображениями до 12 МБ каждая"},400);
    if(videos.some(file=>!file.type.startsWith("video/") || file.size>80*1024*1024)) return json({error:"Видео должно быть до 80 МБ каждое"},400);
    const createdKeys=[];
    try {
      for(const item of allPhotos) {
        const key=`tasks/${id}/photos/${crypto.randomUUID()}`;
        await env.FILES.put(key,item.file.stream(),{httpMetadata:{contentType:item.file.type}});
        createdKeys.push(key);
        await env.DB.prepare("INSERT INTO task_photos(task_id,photo_type,uploaded_by,file_key,content_type) VALUES(?,?,?,?,?)").bind(id,item.type,user.id,key,item.file.type).run();
      }
      for(const file of videos) {
        const key=`tasks/${id}/videos/${crypto.randomUUID()}`;
        await env.FILES.put(key,file.stream(),{httpMetadata:{contentType:file.type}});
        createdKeys.push(key);
        await env.DB.prepare("INSERT INTO task_videos(task_id,uploaded_by,file_key,content_type,original_name,size_bytes) VALUES(?,?,?,?,?,?)").bind(id,user.id,key,file.type,file.name||"video",file.size).run();
      }
      const submittedAt=new Date().toISOString();
      await env.DB.prepare("UPDATE tasks SET completion_comment=?,submitted_at=?,status='На проверке' WHERE id=?").bind(comment,submittedAt,id).run();
      await env.DB.prepare("INSERT INTO task_history(task_id,user_id,old_status,new_status,comment) VALUES(?,?,?,?,?)")
        .bind(id,user.id,access.task.status,"На проверке",comment||"Отчёт отправлен на проверку").run();
      return json({ok:true});
    } catch(e) {
      for(const key of createdKeys) await env.FILES.delete(key).catch(()=>{});
      throw e;
    }
  }
  if(path.startsWith("/api/tasks/") && path.includes("/files/") && method==="GET") {
    const parts=path.split("/"), id=Number(parts[3]), kind=parts[5], fileId=Number(parts[6]);
    const access=await getTaskAccess(env,user,id);
    if(access.error) return access.error;
    let file;
    if(kind==="photo") file=await env.DB.prepare("SELECT file_key,content_type FROM task_photos WHERE id=? AND task_id=?").bind(fileId,id).first();
    else if(kind==="video") file=await env.DB.prepare("SELECT file_key,content_type FROM task_videos WHERE id=? AND task_id=?").bind(fileId,id).first();
    else return json({error:"Неизвестный тип файла"},404);
    if(!file) return json({error:"Файл не найден"},404);
    const object=await env.FILES.get(file.file_key);
    if(!object) return json({error:"Файл отсутствует в хранилище"},404);
    return new Response(object.body,{headers:{"content-type":file.content_type||"application/octet-stream","cache-control":"private, no-store","content-disposition":"inline"}});
  }
  if(path.startsWith("/api/tasks/") && method==="DELETE") {
    if(!adminOnly(user)) return json({error:"Удалять задания может только администратор"},403);
    const id=Number(path.split("/").pop());
    if(!Number.isInteger(id) || id<1) return json({error:"Неверный номер задания"},400);
    const photos=await env.DB.prepare("SELECT file_key FROM task_photos WHERE task_id=?").bind(id).all();
    const videos=await env.DB.prepare("SELECT file_key FROM task_videos WHERE task_id=?").bind(id).all();
    for(const file of [...photos.results,...videos.results]) await env.FILES.delete(file.file_key);
    const result=await env.DB.prepare("DELETE FROM tasks WHERE id=?").bind(id).run();
    if(!result.meta.changes) return json({error:"Задание не найдено"},404);
    return json({ok:true});
  }
  if(path.startsWith("/api/tasks/") && method==="PATCH") {
    const id=Number(path.split("/").pop()), b=await request.json();
    const status=["Новая","В работе","На проверке","Выполнено"].includes(b.status)?b.status:null;
    if(!status) return json({error:"Недопустимый статус"},400);
    const task=await env.DB.prepare("SELECT * FROM tasks WHERE id=?").bind(id).first();
    if(!task) return json({error:"Задание не найдено"},404);
    if(user.role!=="admin" && task.assigned_to!==user.id && task.created_by!==user.id) return json({error:"Нет доступа"},403);
    if(task.status!==status) {
      await env.DB.prepare("UPDATE tasks SET status=? WHERE id=?").bind(status,id).run();
      await env.DB.prepare("INSERT INTO task_history(task_id,user_id,old_status,new_status) VALUES(?,?,?,?)")
        .bind(id,user.id,task.status,status).run();
    }
    return json({ok:true});
  }
  if(path==="/api/checklist" && method==="GET") {
    const date=url.searchParams.get("date")||new Date().toISOString().slice(0,10);
    const rows=adminOnly(user)
      ? await env.DB.prepare(`SELECT i.id,i.title,i.category,e.id entry_id,e.engineer_id,e.check_date,e.result,e.comment,u.full_name engineer_name FROM checklist_items i LEFT JOIN checklist_entries e ON e.item_id=i.id AND e.check_date=? LEFT JOIN users u ON u.id=e.engineer_id WHERE i.active=1 ORDER BY i.sort_order,i.id,e.engineer_id`).bind(date).all()
      : await env.DB.prepare(`SELECT i.id,i.title,i.category,e.id entry_id,e.engineer_id,e.check_date,e.result,e.comment,u.full_name engineer_name FROM checklist_items i LEFT JOIN checklist_entries e ON e.item_id=i.id AND e.engineer_id=? AND e.check_date=? LEFT JOIN users u ON u.id=e.engineer_id WHERE i.active=1 ORDER BY i.sort_order,i.id`).bind(user.id,date).all();
    return json({date,items:rows.results});
  }
  if(path==="/api/checklist/items" && method==="DELETE") {
    if(!adminOnly(user)) return json({error:"Удалять пункты обхода может только администратор"},403);
    const b=await request.json(), itemId=Number(b.itemId);
    if(!Number.isInteger(itemId)||itemId<1) return json({error:"Не выбран пункт обхода"},400);
    const item=await env.DB.prepare("SELECT id FROM checklist_items WHERE id=?").bind(itemId).first();
    if(!item) return json({error:"Пункт обхода не найден"},404);
    await env.DB.prepare("DELETE FROM checklist_entries WHERE item_id=?").bind(itemId).run();
    await env.DB.prepare("DELETE FROM checklist_items WHERE id=?").bind(itemId).run();
    return json({ok:true,deletedHistory:true});
  }
  if(path==="/api/checklist/entries" && method==="DELETE") {
    if(!adminOnly(user)) return json({error:"Удалять обходы может только администратор"},403);
    const b=await request.json(), entryId=Number(b.entryId);
    if(!Number.isInteger(entryId)||entryId<1) return json({error:"Не выбрана запись обхода"},400);
    const r=await env.DB.prepare("DELETE FROM checklist_entries WHERE id=?").bind(entryId).run();
    if(!r.meta.changes) return json({error:"Запись обхода не найдена"},404);
    return json({ok:true});
  }
  if(path==="/api/checklist/items" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const b=await request.json();
    if(!b.title?.trim()) return json({error:"Введите пункт чек-листа"},400);
    const category=String(b.category||"Общие требования").trim()||"Общие требования";
    const r=await env.DB.prepare("INSERT INTO checklist_items(title,category) VALUES(?,?)").bind(b.title.trim(),category).run();
    return json({ok:true,id:r.meta.last_row_id});
  }
  if(path==="/api/checklist/entries" && method==="POST") {
    const b=await request.json();
    if(!b.itemId||!["Выполнено","Нарушение","Не применимо"].includes(b.result)) return json({error:"Проверьте результат обхода"},400);
    const date=b.date||new Date().toISOString().slice(0,10);
    await env.DB.prepare(`INSERT INTO checklist_entries(item_id,engineer_id,check_date,result,comment)
      VALUES(?,?,?,?,?) ON CONFLICT(item_id,engineer_id,check_date) DO UPDATE SET result=excluded.result,comment=excluded.comment`)
      .bind(b.itemId,user.id,date,b.result,b.comment||"").run();
    return json({ok:true});
  }
  if(path==="/api/documents" && method==="GET") {
    const rows=await env.DB.prepare("SELECT id,title,content_type,uploaded_at FROM documents WHERE engineer_id=? ORDER BY uploaded_at DESC").bind(user.id).all();
    return json({documents:rows.results});
  }
  if(path==="/api/documents" && method==="POST") {
    const form=await request.formData(), file=form.get("file"), title=String(form.get("title")||file?.name||"Документ");
    if(!(file instanceof File) || file.size>15*1024*1024) return json({error:"Файл не выбран или превышает 15 МБ"},400);
    const key=`${user.organization_id||"general"}/${user.id}/${crypto.randomUUID()}`;
    await env.FILES.put(key,file.stream(),{httpMetadata:{contentType:file.type||"application/octet-stream"}});
    const r=await env.DB.prepare("INSERT INTO documents(engineer_id,title,file_key,content_type) VALUES(?,?,?,?)")
      .bind(user.id,title,key,file.type||"application/octet-stream").run();
    return json({ok:true,id:r.meta.last_row_id});
  }
  if(path.startsWith("/api/documents/") && method==="GET") {
    const id=Number(path.split("/").pop());
    const doc=await env.DB.prepare("SELECT * FROM documents WHERE id=? AND engineer_id=?").bind(id,user.id).first();
    if(!doc) return json({error:"Документ не найден"},404);
    const object=await env.FILES.get(doc.file_key);
    if(!object) return json({error:"Файл отсутствует в хранилище"},404);
    return new Response(object.body,{headers:{"content-type":doc.content_type||"application/octet-stream","content-disposition":`attachment; filename*=UTF-8''${encodeURIComponent(doc.title)}`,"cache-control":"private, no-store"}});
  }
  return json({error:"Маршрут не найден"},404);
}

export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    if(url.pathname.startsWith("/api/")) {
      try { return await api(request,env); }
      catch(e) { console.error("API_ERROR", url.pathname, e?.stack || String(e)); return json({error:"Внутренняя ошибка сервера",requestId:request.headers.get("cf-ray")||"unknown",detail:env.ENVIRONMENT==="development"?String(e):undefined},500); }
    }
    return env.ASSETS.fetch(request);
  }
};
