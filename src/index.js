
const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers }
  });

const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

async function digest(s) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256"
  }, key, 256);
  return `${salt}.${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(".");
  if (!salt || !expected) return false;
  return (await passwordHash(password, salt)).split(".")[1] === expected;
}

function cookie(request) {
  return (request.headers.get("Cookie") || "")
    .split(";").map(x => x.trim())
    .find(x => x.startsWith("baza_session="))?.slice(13) || null;
}

async function makeSession(user, env) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await digest(token);
  const expires = new Date(Date.now() + 7 * 86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)")
    .bind(tokenHash, user.id, expires).run();
  return token;
}

async function currentUser(request, env) {
  const token = cookie(request);
  if (!token) return null;
  const tokenHash = await digest(token);
  return await env.DB.prepare(`
    SELECT u.id,u.username,u.full_name,u.role,u.organization_id
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>? AND u.active=1
  `).bind(tokenHash, new Date().toISOString()).first();
}

const adminOnly = user => user.role === "admin";

async function getTask(id, user, env) {
  const task = await env.DB.prepare(`
    SELECT t.*,u.full_name AS assigned_name,c.full_name AS creator_name
    FROM tasks t
    LEFT JOIN users u ON u.id=t.assigned_to
    JOIN users c ON c.id=t.created_by
    WHERE t.id=?
  `).bind(id).first();

  if (!task) return { error: json({ error: "Задание не найдено" }, 404) };

  const allowed = user.role === "admin" ||
    task.organization_id === user.organization_id ||
    task.assigned_to === user.id ||
    task.created_by === user.id;

  if (!allowed) return { error: json({ error: "Нет доступа к заданию" }, 403) };
  return { task };
}

async function addHistory(env, taskId, userId, oldStatus, newStatus, comment = "") {
  await env.DB.prepare(`
    INSERT INTO task_history(task_id,user_id,old_status,new_status,comment)
    VALUES(?,?,?,?,?)
  `).bind(taskId, userId, oldStatus, newStatus, comment).run();
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!env.SESSION_SECRET) {
    return json({ error: "Не задан SESSION_SECRET в настройках Worker" }, 500);
  }

  // Первоначальная настройка администратора
  if (path === "/api/setup" && method === "POST") {
    const body = await request.json();
    if (!env.SETUP_SECRET || body.setupSecret !== env.SETUP_SECRET) {
      return json({ error: "Неверный код первоначальной настройки" }, 403);
    }
    const exists = await env.DB.prepare("SELECT id FROM users LIMIT 1").first();
    if (exists) return json({ error: "Первый администратор уже создан" }, 409);
    if (!body.username || !body.password || body.password.length < 12 || !body.fullName) {
      return json({ error: "Укажите ФИО, логин и пароль не короче 12 символов" }, 400);
    }
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(body.password, salt);
    const result = await env.DB.prepare(
      "INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,'admin')"
    ).bind(body.username, body.fullName, hash).run();
    return json({ ok: true, userId: result.meta.last_row_id });
  }

  // Вход
  if (path === "/api/login" && method === "POST") {
    const body = await request.json();
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE username=? AND active=1"
    ).bind(body.username || "").first();

    if (!user || !(await verifyPassword(body.password || "", user.password_hash))) {
      return json({ error: "Неверный логин или пароль" }, 401);
    }

    const token = await makeSession(user, env);
    return json({
      ok: true,
      user: { id: user.id, fullName: user.full_name, role: user.role }
    }, 200, {
      "Set-Cookie": `baza_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });
  }

  if (path === "/api/logout" && method === "POST") {
    const token = cookie(request);
    if (token) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?")
        .bind(await digest(token)).run();
    }
    return json({ ok: true }, 200, {
      "Set-Cookie": "baza_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    });
  }

  const user = await currentUser(request, env);
  if (!user) return json({ error: "Требуется вход в систему" }, 401);

  if (path === "/api/me" && method === "GET") return json({ user });

  // Организации
  if (path === "/api/organizations" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,name FROM organizations ORDER BY name").all();
    return json({ organizations: rows.results });
  }

  if (path === "/api/organizations" && method === "POST") {
    if (!adminOnly(user)) return json({ error: "Недостаточно прав" }, 403);
    const body = await request.json();
    if (!body.name?.trim()) return json({ error: "Введите название организации" }, 400);
    try {
      const r = await env.DB.prepare("INSERT INTO organizations(name) VALUES(?)")
        .bind(body.name.trim()).run();
      return json({ ok: true, id: r.meta.last_row_id });
    } catch {
      return json({ error: "Такая организация уже существует" }, 409);
    }
  }

  // Пользователи
  if (path === "/api/users" && method === "GET") {
    if (!adminOnly(user)) return json({ error: "Недостаточно прав" }, 403);
    const rows = await env.DB.prepare(`
      SELECT id,username,full_name,role,organization_id,active
      FROM users ORDER BY full_name
    `).all();
    return json({ users: rows.results });
  }

  if (path === "/api/access-audit" && method === "GET") {
    if (!adminOnly(user)) return json({ error: "Недостаточно прав" }, 403);
    const rows = await env.DB.prepare(`
      SELECT a.id,a.action,a.created_at,
        actor.full_name AS actor_name,
        target.full_name AS target_name,
        target.username AS target_username
      FROM access_audit a
      LEFT JOIN users actor ON actor.id=a.actor_id
      LEFT JOIN users target ON target.id=a.target_user_id
      ORDER BY a.id DESC LIMIT 100
    `).all();
    return json({ events: rows.results });
  }

  if (path === "/api/users" && method === "POST") {
    if (!adminOnly(user)) return json({ error: "Недостаточно прав" }, 403);
    const b = await request.json();
    if (b.role !== "admin") {
      const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='engineer' AND active=1").first();
      if ((count?.n || 0) >= 2) return json({ error: "Можно создать только двух активных ответственных инженеров" }, 400);
    }
    if (!b.username || !b.fullName || !b.password || b.password.length < 12) {
      return json({ error: "Заполните ФИО, логин и пароль от 12 символов" }, 400);
    }
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(b.password, salt);
    try {
      const r = await env.DB.prepare(`
        INSERT INTO users(username,full_name,password_hash,role,organization_id)
        VALUES(?,?,?,?,?)
      `).bind(b.username, b.fullName, hash, b.role === "admin" ? "admin" : "engineer",
        b.organizationId || null).run();
      await env.DB.prepare("INSERT INTO access_audit(actor_id,target_user_id,action) VALUES(?,?,?)")
        .bind(user.id, r.meta.last_row_id, "Создан пользователь").run();
      return json({ ok: true, id: r.meta.last_row_id });
    } catch {
      return json({ error: "Логин уже занят" }, 409);
    }
  }

  // Список заданий
  if (path === "/api/tasks" && method === "GET") {
    const rows = await env.DB.prepare(`
      SELECT t.*,u.full_name AS assigned_name,c.full_name AS creator_name,
        r.full_name AS reviewer_name
      FROM tasks t
      LEFT JOIN users u ON u.id=t.assigned_to
      JOIN users c ON c.id=t.created_by
      LEFT JOIN users r ON r.id=t.reviewed_by
      WHERE (?='admin' OR t.organization_id IS ? OR t.assigned_to=? OR t.created_by=?)
      ORDER BY CASE WHEN t.status='Выполнено' THEN 1 ELSE 0 END,t.due_date
    `).bind(user.role, user.organization_id, user.id, user.id).all();
    return json({ tasks: rows.results });
  }

  // Создание задания
  if (path === "/api/tasks" && method === "POST") {
    const b = await request.json();
    if (!b.title?.trim()) return json({ error: "Введите название задания" }, 400);

    const assigned = b.assignedTo ? Number(b.assignedTo) : null;
    if (assigned) {
      const target = await env.DB.prepare(
        "SELECT id,organization_id,active FROM users WHERE id=?"
      ).bind(assigned).first();
      if (!target || !target.active) return json({ error: "Исполнитель не найден или отключён" }, 400);
      if (target.organization_id !== user.organization_id && user.role !== "admin") {
        return json({ error: "Исполнитель относится к другой организации" }, 400);
      }
    }

    const r = await env.DB.prepare(`
      INSERT INTO tasks(organization_id,title,description,assigned_to,created_by,due_date)
      VALUES(?,?,?,?,?,?)
    `).bind(user.organization_id, b.title.trim(), b.description || "",
      assigned, user.id, b.dueDate || null).run();

    await addHistory(env, r.meta.last_row_id, user.id, null, "Новая", "Задание создано");
    return json({ ok: true, id: r.meta.last_row_id });
  }

  // Фото задания: список и загрузка
  const photoListMatch = path.match(/^\/api\/tasks\/(\d+)\/photos$/);
  if (photoListMatch) {
    const id = Number(photoListMatch[1]);
    const access = await getTask(id, user, env);
    if (access.error) return access.error;

    if (method === "GET") {
      const rows = await env.DB.prepare(`
        SELECT p.id,p.photo_type,p.uploaded_by,p.content_type,p.created_at,u.full_name
        FROM task_photos p JOIN users u ON u.id=p.uploaded_by
        WHERE p.task_id=? ORDER BY p.created_at,p.id
      `).bind(id).all();
      return json({ photos: rows.results });
    }

    if (method === "POST") {
      const task = access.task;
      const allowedUploader = user.role === "admin" ||
        task.assigned_to === user.id || task.created_by === user.id;
      if (!allowedUploader) return json({ error: "Нет прав для загрузки фото" }, 403);

      const form = await request.formData();
      const file = form.get("file");
      const type = String(form.get("photoType") || "");

      if (!(file instanceof File) || !file.size || file.size > 5 * 1024 * 1024) {
        return json({ error: "Выберите фотографию размером не более 5 МБ" }, 400);
      }
      if (!file.type.startsWith("image/")) {
        return json({ error: "Можно загружать только изображения" }, 400);
      }
      if (!["before", "after"].includes(type)) {
        return json({ error: "Укажите тип фотографии: до или после" }, 400);
      }
      if (!env.FILES) return json({ error: "Хранилище фотографий не подключено" }, 500);

      const key = `tasks/${id}/${type}/${crypto.randomUUID()}`;
      await env.FILES.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });
      const r = await env.DB.prepare(`
        INSERT INTO task_photos(task_id,photo_type,uploaded_by,file_key,content_type)
        VALUES(?,?,?,?,?)
      `).bind(id, type, user.id, key, file.type).run();

      return json({ ok: true, id: r.meta.last_row_id });
    }
  }

  // Получение файла фотографии
  const photoFileMatch = path.match(/^\/api\/tasks\/(\d+)\/photos\/(\d+)\/file$/);
  if (photoFileMatch && method === "GET") {
    const taskId = Number(photoFileMatch[1]);
    const photoId = Number(photoFileMatch[2]);
    const access = await getTask(taskId, user, env);
    if (access.error) return access.error;

    const photo = await env.DB.prepare(
      "SELECT * FROM task_photos WHERE id=? AND task_id=?"
    ).bind(photoId, taskId).first();
    if (!photo) return json({ error: "Фотография не найдена" }, 404);

    const object = await env.FILES.get(photo.file_key);
    if (!object) return json({ error: "Файл отсутствует в хранилище" }, 404);

    return new Response(object.body, {
      headers: {
        "content-type": photo.content_type,
        "cache-control": "private, no-store"
      }
    });
  }

  // Видеоотчёт: список и загрузка
  const videoListMatch = path.match(/^\/api\/tasks\/(\d+)\/videos$/);
  if (videoListMatch) {
    const id = Number(videoListMatch[1]);
    const access = await getTask(id, user, env);
    if (access.error) return access.error;

    if (method === "GET") {
      const rows = await env.DB.prepare(`
        SELECT v.id,v.uploaded_by,v.content_type,v.original_name,
          v.size_bytes,v.created_at,u.full_name
        FROM task_videos v JOIN users u ON u.id=v.uploaded_by
        WHERE v.task_id=? ORDER BY v.created_at,v.id
      `).bind(id).all();
      return json({ videos: rows.results });
    }

    if (method === "POST") {
      const task = access.task;
      const allowedUploader = user.role === "admin" ||
        task.assigned_to === user.id || task.created_by === user.id;
      if (!allowedUploader) return json({ error: "Нет прав для загрузки видео" }, 403);

      const form = await request.formData();
      const file = form.get("file");

      if (!(file instanceof File) || !file.size) {
        return json({ error: "Выберите видеофайл" }, 400);
      }
      if (file.size > 50 * 1024 * 1024) {
        return json({ error: "Размер видео не должен превышать 50 МБ" }, 400);
      }
      if (!file.type.startsWith("video/")) {
        return json({ error: "Можно загружать только видеофайлы" }, 400);
      }
      if (!env.FILES) return json({ error: "Хранилище файлов не подключено" }, 500);

      const safeName = String(file.name || "video")
        .replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 100);
      const key = `tasks/${id}/videos/${crypto.randomUUID()}-${safeName}`;

      await env.FILES.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });

      const r = await env.DB.prepare(`
        INSERT INTO task_videos
        (task_id,uploaded_by,file_key,content_type,original_name,size_bytes)
        VALUES(?,?,?,?,?,?)
      `).bind(id, user.id, key, file.type, file.name || "Видеоотчёт", file.size).run();

      return json({ ok: true, id: r.meta.last_row_id });
    }
  }

  // Просмотр видеоотчёта
  const videoFileMatch = path.match(/^\/api\/tasks\/(\d+)\/videos\/(\d+)\/file$/);
  if (videoFileMatch && method === "GET") {
    const taskId = Number(videoFileMatch[1]);
    const videoId = Number(videoFileMatch[2]);
    const access = await getTask(taskId, user, env);
    if (access.error) return access.error;

    const video = await env.DB.prepare(
      "SELECT * FROM task_videos WHERE id=? AND task_id=?"
    ).bind(videoId, taskId).first();

    if (!video) return json({ error: "Видеоотчёт не найден" }, 404);

    const object = await env.FILES.get(video.file_key);
    if (!object) return json({ error: "Видео отсутствует в хранилище" }, 404);

    return new Response(object.body, {
      headers: {
        "content-type": video.content_type,
        "content-length": String(video.size_bytes),
        "cache-control": "private, no-store",
        "content-disposition": "inline"
      }
    });
  }

  // История задания
  const historyMatch = path.match(/^\/api\/tasks\/(\d+)\/history$/);
  if (historyMatch && method === "GET") {
    const id = Number(historyMatch[1]);
    const access = await getTask(id, user, env);
    if (access.error) return access.error;

    const rows = await env.DB.prepare(`
      SELECT h.*,u.full_name
      FROM task_history h JOIN users u ON u.id=h.user_id
      WHERE h.task_id=? ORDER BY h.created_at DESC,h.id DESC
    `).bind(id).all();
    return json({ history: rows.results });
  }

  // Действия с заданием и проверка
  const taskMatch = path.match(/^\/api\/tasks\/(\d+)$/);
  if (taskMatch && method === "PATCH") {
    const id = Number(taskMatch[1]);
    const body = await request.json();
    const access = await getTask(id, user, env);
    if (access.error) return access.error;
    const task = access.task;

    const isWorker = task.assigned_to === user.id || task.created_by === user.id;
    const action = body.action;

    if (action === "start") {
      if (!isWorker && !adminOnly(user)) return json({ error: "Нет прав для начала работы" }, 403);
      if (task.status !== "Новая") return json({ error: "Начать можно только новое задание" }, 400);
      await env.DB.prepare("UPDATE tasks SET status='В работе' WHERE id=?").bind(id).run();
      await addHistory(env, id, user.id, task.status, "В работе", "Работа начата");
      return json({ ok: true });
    }

    if (action === "submit") {
      if (!isWorker && !adminOnly(user)) return json({ error: "Нет прав для отправки отчёта" }, 403);
      if (task.status !== "В работе") return json({ error: "На проверку можно отправить задание со статусом «В работе»" }, 400);
      if (!body.comment?.trim()) return json({ error: "Напишите отчёт о выполненной работе" }, 400);

      const after = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM task_photos WHERE task_id=? AND photo_type='after'"
      ).bind(id).first();
      if (!after || after.n < 1) {
        return json({ error: "Перед отправкой добавьте хотя бы одну фотографию после устранения" }, 400);
      }

      await env.DB.prepare(`
        UPDATE tasks SET status='На проверке',completion_comment=?,submitted_at=CURRENT_TIMESTAMP
        WHERE id=?
      `).bind(body.comment.trim(), id).run();
      await addHistory(env, id, user.id, task.status, "На проверке", body.comment.trim());
      return json({ ok: true });
    }

    if (action === "approve") {
      if (!adminOnly(user)) return json({ error: "Принять задание может только администратор" }, 403);
      if (task.status !== "На проверке") return json({ error: "Задание не ожидает проверки" }, 400);

      const comment = String(body.comment || "").trim();
      await env.DB.prepare(`
        UPDATE tasks SET status='Выполнено',completed_at=CURRENT_TIMESTAMP,
          reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,review_comment=? WHERE id=?
      `).bind(user.id, comment, id).run();
      await addHistory(env, id, user.id, task.status, "Выполнено", comment || "Работа принята");
      return json({ ok: true });
    }

    if (action === "return") {
      if (!adminOnly(user)) return json({ error: "Вернуть на доработку может только администратор" }, 403);
      if (task.status !== "На проверке") return json({ error: "Задание не ожидает проверки" }, 400);
      if (!body.comment?.trim()) return json({ error: "Укажите причину возврата на доработку" }, 400);

      await env.DB.prepare(`
        UPDATE tasks SET status='В работе',reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,
          review_comment=?,completed_at=NULL WHERE id=?
      `).bind(user.id, body.comment.trim(), id).run();
      await addHistory(env, id, user.id, task.status, "В работе", body.comment.trim());
      return json({ ok: true });
    }

    return json({ error: "Неизвестное действие с заданием" }, 400);
  }

  // Ежедневный обход
  if (path === "/api/checklist" && method === "GET") {
    const date = url.searchParams.get("date") || new Date().toISOString().slice(0, 10);
    const rows = await env.DB.prepare(`
      SELECT i.id,i.title,e.result,e.comment FROM checklist_items i
      LEFT JOIN checklist_entries e ON e.item_id=i.id AND e.engineer_id=? AND e.check_date=?
      WHERE i.active=1 AND (i.organization_id IS NULL OR i.organization_id IS ?)
      ORDER BY i.sort_order,i.id
    `).bind(user.id, date, user.organization_id).all();
    return json({ date, items: rows.results });
  }

  if (path === "/api/checklist/items" && method === "POST") {
    if (!adminOnly(user)) return json({ error: "Недостаточно прав" }, 403);
    const b = await request.json();
    if (!b.title?.trim()) return json({ error: "Введите пункт чек-листа" }, 400);
    const r = await env.DB.prepare(
      "INSERT INTO checklist_items(organization_id,title) VALUES(?,?)"
    ).bind(b.organizationId || null, b.title.trim()).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }

  if (path === "/api/checklist/entries" && method === "POST") {
    const b = await request.json();
    if (!b.itemId || !["Выполнено", "Нарушение", "Не применимо"].includes(b.result)) {
      return json({ error: "Проверьте результат обхода" }, 400);
    }
    const date = b.date || new Date().toISOString().slice(0, 10);
    await env.DB.prepare(`
      INSERT INTO checklist_entries(item_id,engineer_id,check_date,result,comment)
      VALUES(?,?,?,?,?)
      ON CONFLICT(item_id,engineer_id,check_date)
      DO UPDATE SET result=excluded.result,comment=excluded.comment
    `).bind(b.itemId, user.id, date, b.result, b.comment || "").run();
    return json({ ok: true });
  }

  // Документы инженера
  if (path === "/api/documents" && method === "GET") {
    const rows = await env.DB.prepare(`
      SELECT id,title,content_type,uploaded_at FROM documents
      WHERE engineer_id=? ORDER BY uploaded_at DESC
    `).bind(user.id).all();
    return json({ documents: rows.results });
  }

  if (path === "/api/documents" && method === "POST") {
    const form = await request.formData();
    const file = form.get("file");
    const title = String(form.get("title") || file?.name || "Документ");
    if (!(file instanceof File) || file.size > 15 * 1024 * 1024) {
      return json({ error: "Файл не выбран или превышает 15 МБ" }, 400);
    }
    const key = `${user.organization_id || "general"}/${user.id}/${crypto.randomUUID()}`;
    await env.FILES.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || "application/octet-stream" }
    });
    const r = await env.DB.prepare(`
      INSERT INTO documents(organization_id,engineer_id,title,file_key,content_type)
      VALUES(?,?,?,?,?)
    `).bind(user.organization_id, user.id, title, key, file.type || "application/octet-stream").run();
    return json({ ok: true, id: r.meta.last_row_id });
  }

  if (path.startsWith("/api/documents/") && method === "GET") {
    const id = Number(path.split("/").pop());
    const doc = await env.DB.prepare(
      "SELECT * FROM documents WHERE id=? AND engineer_id=?"
    ).bind(id, user.id).first();
    if (!doc) return json({ error: "Документ не найден" }, 404);
    const object = await env.FILES.get(doc.file_key);
    if (!object) return json({ error: "Файл отсутствует в хранилище" }, 404);
    return new Response(object.body, {
      headers: {
        "content-type": doc.content_type || "application/octet-stream",
        "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(doc.title)}`,
        "cache-control": "private, no-store"
      }
    });
  }


  // Фотоотчёты инженеров с проверкой администратором
  if (path === "/api/photo-reports" && method === "GET") {
    const sql = `SELECT p.id,p.engineer_id,p.organization_id,p.description,p.status,p.review_comment,p.created_at,p.reviewed_at,u.full_name AS engineer_name,o.name AS organization_name,r.full_name AS reviewer_name FROM photo_reports p JOIN users u ON u.id=p.engineer_id LEFT JOIN organizations o ON o.id=p.organization_id LEFT JOIN users r ON r.id=p.reviewed_by `;
    const rows = user.role === "admin"
      ? await env.DB.prepare(sql + " ORDER BY CASE p.status WHEN 'На проверке' THEN 0 WHEN 'Отклонено' THEN 1 ELSE 2 END,p.created_at DESC").all()
      : await env.DB.prepare(sql + " WHERE p.engineer_id=? ORDER BY p.created_at DESC").bind(user.id).all();
    return json({ reports: rows.results });
  }

  if (path === "/api/photo-reports" && method === "POST") {
    if (user.role !== "engineer") return json({ error: "Фотоотчёт отправляет ответственный инженер" }, 403);
    const form = await request.formData();
    const file = form.get("file");
    const description = String(form.get("description") || "").trim();
    if (!(file instanceof File) || !file.size || file.size > 8 * 1024 * 1024) return json({ error: "Выберите фотографию размером не более 8 МБ" }, 400);
    if (!file.type.startsWith("image/")) return json({ error: "Можно отправлять только фотографии" }, 400);
    if (!description) return json({ error: "Добавьте описание фотографии" }, 400);
    if (!env.FILES) return json({ error: "Хранилище фотографий не подключено" }, 500);
    const key = "photo-reports/" + user.id + "/" + crypto.randomUUID();
    await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
    const r = await env.DB.prepare("INSERT INTO photo_reports(engineer_id,organization_id,description,file_key,content_type) VALUES(?,?,?,?,?)").bind(user.id,user.organization_id,description,key,file.type).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }

  const reportFileMatch = path.match(/^\/api\/photo-reports\/(\d+)\/file$/);
  if (reportFileMatch && method === "GET") {
    const report = await env.DB.prepare("SELECT * FROM photo_reports WHERE id=?").bind(Number(reportFileMatch[1])).first();
    if (!report) return json({ error: "Фотоотчёт не найден" }, 404);
    if (user.role !== "admin" && report.engineer_id !== user.id) return json({ error: "Нет доступа к этой фотографии" }, 403);
    const object = await env.FILES.get(report.file_key);
    if (!object) return json({ error: "Файл отсутствует в хранилище" }, 404);
    return new Response(object.body, { headers: { "content-type": report.content_type, "cache-control": "private, no-store" } });
  }

  const reportActionMatch = path.match(/^\/api\/photo-reports\/(\d+)$/);
  if (reportActionMatch && method === "PATCH") {
    if (!adminOnly(user)) return json({ error: "Подтвердить или отклонить фото может только администратор" }, 403);
    const body = await request.json(); const id = Number(reportActionMatch[1]);
    const report = await env.DB.prepare("SELECT * FROM photo_reports WHERE id=?").bind(id).first();
    if (!report) return json({ error: "Фотоотчёт не найден" }, 404);
    if (report.status !== "На проверке") return json({ error: "Этот фотоотчёт уже проверен" }, 400);
    if (body.action === "approve") {
      await env.DB.prepare("UPDATE photo_reports SET status='Подтверждено',reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,review_comment='' WHERE id=?").bind(user.id,id).run();
      return json({ ok: true });
    }
    if (body.action === "reject") {
      await env.DB.prepare("UPDATE photo_reports SET status='Отклонено',reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,review_comment='' WHERE id=?").bind(user.id,id).run();
      return json({ ok: true });
    }
    return json({ error: "Неизвестное действие" }, 400);
  }
  // Certificate register and expiry control
  if (path === "/api/certificates" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,employee_name,position,certificate_number,valid_until,updated_at FROM certificates ORDER BY valid_until,employee_name").all();
    return json({ certificates: rows.results });
  }
  if (path === "/api/certificates" && method === "POST") {
    if (!adminOnly(user)) return json({ error: "Только администратор может добавлять удостоверения" }, 403);
    const b = await request.json();
    if (!b.employeeName?.trim() || !/^\d{4}-\d{2}-\d{2}$/.test(b.validUntil || "")) return json({ error: "Укажите ФИО и дату окончания" }, 400);
    const r = await env.DB.prepare("INSERT INTO certificates(employee_name,position,certificate_number,valid_until,updated_by) VALUES(?,?,?,?,?)")
      .bind(b.employeeName.trim(), b.position || "", b.certificateNumber || "", b.validUntil, user.id).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }
  const certificateMatch = path.match(/^\/api\/certificates\/(\d+)$/);
  if (certificateMatch && method === "PATCH") {
    if (!adminOnly(user)) return json({ error: "Только администратор может изменять удостоверения" }, 403);
    const b = await request.json();
    if (!b.employeeName?.trim() || !/^\d{4}-\d{2}-\d{2}$/.test(b.validUntil || "")) return json({ error: "Проверьте ФИО и дату окончания" }, 400);
    const result = await env.DB.prepare("UPDATE certificates SET employee_name=?,position=?,certificate_number=?,valid_until=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(b.employeeName.trim(), b.position || "", b.certificateNumber || "", b.validUntil, user.id, Number(certificateMatch[1])).run();
    if (!result.meta.changes) return json({ error: "Удостоверение не найдено" }, 404);
    return json({ ok: true });
  }

  return json({ error: "Маршрут не найден" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env);
      } catch (e) {
        console.error("API error:", String(e));
        return json({ error: "Внутренняя ошибка сервера" }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
