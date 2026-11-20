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
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:210000,hash:"SHA-256"},key,256);
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
async function api(request, env) {
  const url = new URL(request.url), path=url.pathname, method=request.method;
  if (!env.SESSION_SECRET) return json({error:"Не задан SESSION_SECRET в настройках Worker"},500);

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
    let sql="SELECT id,employee_name,position,employer,instruction_date,form_o86_value,form_086_value,has_medical_certificate,slinger_certificate FROM employees WHERE batch_id=?";
    const args=[state.active_batch_id];
    if(q){sql+=" AND employee_name LIKE ?";args.push("%"+q+"%");}
    if(slingers) sql+=" AND COALESCE(slinger_certificate,'')<>'' AND LOWER(slinger_certificate) NOT IN ('нет','no','-','0')";
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
      statements.push(env.DB.prepare(`INSERT INTO employees(batch_id,source_key,employee_name,position,employer,instruction_date,form_o86_value,form_086_value,has_medical_certificate,slinger_certificate)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(batch_id,source_key) DO UPDATE SET employee_name=excluded.employee_name,position=excluded.position,employer=excluded.employer,instruction_date=excluded.instruction_date,form_o86_value=excluded.form_o86_value,form_086_value=excluded.form_086_value,has_medical_certificate=excluded.has_medical_certificate,slinger_certificate=excluded.slinger_certificate,updated_at=CURRENT_TIMESTAMP`)
        .bind(String(b.batchId),sourceKey,name,String(r.position||""),String(r.employer||""),r.instruction_date||null,String(r.form_o86_value||""),String(r.form_086_value||""),r.has_medical_certificate?1:0,String(r.slinger_certificate||"")));
    }
    if(statements.length) await env.DB.batch(statements);
    if(b.publish===true) {
      await env.DB.prepare("UPDATE employee_import_state SET active_batch_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=1").bind(String(b.batchId)).run();
      await env.DB.prepare("DELETE FROM employees WHERE batch_id<>?").bind(String(b.batchId)).run();
    }
    return json({ok:true,saved:statements.length,published:b.publish===true});
  }
  if(path==="/api/organizations" && method==="GET") {
    const rows=await env.DB.prepare("SELECT id,name FROM organizations ORDER BY name").all();
    return json({organizations:rows.results});
  }
  if(path==="/api/organizations" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const body=await request.json();
    if(!body.name?.trim()) return json({error:"Введите название организации"},400);
    try { const r=await env.DB.prepare("INSERT INTO organizations(name) VALUES(?)").bind(body.name.trim()).run(); return json({ok:true,id:r.meta.last_row_id}); }
    catch { return json({error:"Такая организация уже существует"},409); }
  }
  if(path==="/api/users" && method==="GET") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const rows=await env.DB.prepare("SELECT id,username,full_name,role,organization_id,active FROM users ORDER BY full_name").all();
    return json({users:rows.results});
  }
  if(path==="/api/users" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const b=await request.json();
    if(!b.username||!b.fullName||!b.password||b.password.length<12) return json({error:"Заполните ФИО, логин и пароль от 12 символов"},400);
    const salt=b64(crypto.getRandomValues(new Uint8Array(16))), hash=await passwordHash(b.password,salt);
    try { const r=await env.DB.prepare("INSERT INTO users(username,full_name,password_hash,role,organization_id) VALUES(?,?,?,?,?)").bind(b.username,b.fullName,hash,b.role==="admin"?"admin":"engineer",b.organizationId||null).run(); return json({ok:true,id:r.meta.last_row_id}); }
    catch { return json({error:"Логин уже занят"},409); }
  }
  if(path==="/api/tasks" && method==="GET") {
    const rows=await env.DB.prepare(`SELECT t.*,u.full_name assigned_name,c.full_name creator_name
      FROM tasks t LEFT JOIN users u ON u.id=t.assigned_to JOIN users c ON c.id=t.created_by
      WHERE (?='admin' OR t.organization_id IS ? OR t.assigned_to=? OR t.created_by=?)
      ORDER BY CASE WHEN t.status='Выполнено' THEN 1 ELSE 0 END,t.due_date`).bind(user.role,user.organization_id,user.id,user.id).all();
    return json({tasks:rows.results});
  }
  if(path==="/api/tasks" && method==="POST") {
    const b=await request.json();
    if(!b.title?.trim()) return json({error:"Введите название задания"},400);
    const r=await env.DB.prepare("INSERT INTO tasks(organization_id,title,description,assigned_to,created_by,due_date) VALUES(?,?,?,?,?,?)")
      .bind(user.organization_id,b.title.trim(),b.description||"",b.assignedTo||null,user.id,b.dueDate||null).run();
    return json({ok:true,id:r.meta.last_row_id});
  }
  if(path.startsWith("/api/tasks/") && method==="PATCH") {
    const id=Number(path.split("/").pop()), b=await request.json();
    const status=["Новая","В работе","На проверке","Выполнено"].includes(b.status)?b.status:null;
    if(!status) return json({error:"Недопустимый статус"},400);
    const task=await env.DB.prepare("SELECT * FROM tasks WHERE id=?").bind(id).first();
    if(!task) return json({error:"Задание не найдено"},404);
    if(user.role!=="admin" && task.assigned_to!==user.id && task.created_by!==user.id) return json({error:"Нет доступа"},403);
    await env.DB.prepare("UPDATE tasks SET status=? WHERE id=?").bind(status,id).run();
    return json({ok:true});
  }
  if(path==="/api/checklist" && method==="GET") {
    const date=url.searchParams.get("date")||new Date().toISOString().slice(0,10);
    const rows=await env.DB.prepare(`SELECT i.id,i.title,e.result,e.comment FROM checklist_items i
      LEFT JOIN checklist_entries e ON e.item_id=i.id AND e.engineer_id=? AND e.check_date=?
      WHERE i.active=1 AND (i.organization_id IS NULL OR i.organization_id IS ?) ORDER BY i.sort_order,i.id`)
      .bind(user.id,date,user.organization_id).all();
    return json({date,items:rows.results});
  }
  if(path==="/api/checklist/items" && method==="POST") {
    if(!adminOnly(user)) return json({error:"Недостаточно прав"},403);
    const b=await request.json();
    if(!b.title?.trim()) return json({error:"Введите пункт чек-листа"},400);
    const r=await env.DB.prepare("INSERT INTO checklist_items(organization_id,title) VALUES(?,?)").bind(b.organizationId||null,b.title.trim()).run();
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
    const r=await env.DB.prepare("INSERT INTO documents(organization_id,engineer_id,title,file_key,content_type) VALUES(?,?,?,?,?)")
      .bind(user.organization_id,user.id,title,key,file.type||"application/octet-stream").run();
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
      catch(e) { return json({error:"Внутренняя ошибка сервера",detail:env.ENVIRONMENT==="development"?String(e):undefined},500); }
    }
    return env.ASSETS.fetch(request);
  }
};
