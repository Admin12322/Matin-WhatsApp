require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const GRAPH_VERSION = process.env.META_GRAPH_VERSION;
const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const DB_FILE = path.join(DATA_DIR, "db.json");

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random value of at least 32 characters.");
  process.exit(1);
}
if (!GRAPH_VERSION || !/^v\d+\.\d+$/.test(GRAPH_VERSION)) {
  console.error("Set META_GRAPH_VERSION in .env to a current Graph API version, e.g. vXX.X from Meta.");
  process.exit(1);
}

const initialDb = () => ({ users: [], devices: [], conversations: [], messages: [], events: [] });
let db = initialDb();
let writeQueue = Promise.resolve();

async function saveDb() {
  const snapshot = JSON.stringify(db, null, 2);
  writeQueue = writeQueue.then(() => fsp.writeFile(DB_FILE, snapshot, "utf8"));
  return writeQueue;
}
async function loadDb() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(UPLOAD_DIR, { recursive: true });
  try { db = JSON.parse(await fsp.readFile(DB_FILE, "utf8")); }
  catch {
    db = initialDb();
    const password = process.env.ADMIN_PASSWORD || "ChangeThisNow123!";
    db.users.push({
      id: crypto.randomUUID(), name: process.env.ADMIN_NAME || "Administrator",
      email: (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase(),
      passwordHash: await bcrypt.hash(password, 12), role: "admin", team: "Management",
      active: true, createdAt: new Date().toISOString()
    });
    await saveDb();
    console.log(`First admin created: ${process.env.ADMIN_EMAIL || "admin@example.com"}`);
    console.log("Change the initial admin password after your first login.");
  }
}
const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const cleanUser = u => ({ id:u.id, name:u.name, email:u.email, role:u.role, team:u.team, active:u.active, createdAt:u.createdAt });
const maskPhone = p => {
  const digits = String(p || "").replace(/\D/g, "");
  if (digits.length <= 5) return "•••••";
  return digits.slice(0, Math.min(4, digits.length - 4)) + "••••••" + digits.slice(-3);
};
const phoneFor = (user, conversation) => user.role === "admin" ? conversation.customerPhone : maskPhone(conversation.customerPhone);

app.use(helmet({ crossOriginResourcePolicy: { policy: "same-site" } }));
app.use(express.json({ limit: "2mb", verify: (req, res, buf) => { if (req.originalUrl === "/webhook") req.rawBody = Buffer.from(buf); } }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 180, standardHeaders: "draft-7", legacyHeaders: false }));

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    const found = db.users.find(u => u.id === req.user.id && u.active);
    if (!found) return res.status(401).json({ error: "Account disabled or unavailable." });
    req.userRecord = found;
    next();
  } catch { return res.status(401).json({ error: "Please sign in again." }); }
}
const adminOnly = (req,res,next) => req.user.role === "admin" ? next() : res.status(403).json({ error:"Admin permission required." });
function canAccessConversation(user, c) {
  if (user.role === "admin") return true;
  return c.assignedTo === user.id && c.deviceId && db.devices.some(d => d.id === c.deviceId && d.assignedUserIds.includes(user.id));
}
function visibleConversation(user, c) {
  const device = db.devices.find(d => d.id === c.deviceId);
  return {
    id:c.id, deviceId:c.deviceId, deviceName:device?.name || "Unassigned device",
    customerPhone:phoneFor(user,c), customerName:c.customerName || "WhatsApp customer",
    lastMessage:c.lastMessage || "", lastMessageAt:c.lastMessageAt || c.createdAt,
    unread:c.unread || 0, assignedTo:c.assignedTo || null, status:c.status || "open"
  };
}
function requireConversation(req,res,next) {
  const c = db.conversations.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({error:"Conversation not found."});
  if (!canAccessConversation(req.user,c)) return res.status(403).json({error:"This conversation is not assigned to you."});
  req.conversation = c; next();
}
function deviceForUser(user, deviceId) {
  const d = db.devices.find(x => x.id === deviceId);
  if (!d) return null;
  if (user.role !== "admin" && !d.assignedUserIds.includes(user.id)) return null;
  return d;
}

app.post("/api/auth/login", async (req,res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const u = db.users.find(x => x.email === email && x.active);
  if (!u || !(await bcrypt.compare(password,u.passwordHash))) return res.status(401).json({error:"Email or password is incorrect."});
  const token = jwt.sign({id:u.id, role:u.role}, JWT_SECRET, {expiresIn:"12h"});
  res.json({token, user:cleanUser(u)});
});
app.get("/api/me", auth, (req,res) => res.json({user:cleanUser(req.userRecord)}));
app.post("/api/auth/change-password", auth, async (req,res) => {
  const oldPassword = String(req.body.oldPassword || "");
  const newPassword = String(req.body.newPassword || "");
  if (newPassword.length < 12) return res.status(400).json({error:"Use at least 12 characters for the new password."});
  if (!(await bcrypt.compare(oldPassword,req.userRecord.passwordHash))) return res.status(400).json({error:"Current password is incorrect."});
  req.userRecord.passwordHash = await bcrypt.hash(newPassword,12); await saveDb(); res.json({ok:true});
});

app.get("/api/dashboard", auth, (req,res) => {
  const devices = db.devices.filter(d => req.user.role === "admin" || d.assignedUserIds.includes(req.user.id));
  const conversations = db.conversations.filter(c => canAccessConversation(req.user,c));
  res.json({
    users:req.user.role === "admin" ? db.users.length : undefined,
    devices:devices.length, onlineDevices:devices.filter(d=>d.status==="connected").length,
    conversations:conversations.length, unread:conversations.reduce((n,c)=>n+(c.unread||0),0)
  });
});
app.get("/api/users", auth, adminOnly, (req,res) => res.json(db.users.map(cleanUser)));
app.post("/api/users", auth, adminOnly, async (req,res) => {
  const {name,email,password,role="agent",team="General"} = req.body;
  if (!name || !email || !password || password.length < 12) return res.status(400).json({error:"Name, email and a password of at least 12 characters are required."});
  if (!["admin","agent"].includes(role)) return res.status(400).json({error:"Invalid role."});
  if (db.users.some(u=>u.email===String(email).trim().toLowerCase())) return res.status(409).json({error:"That email already exists."});
  const u={id:id(),name:String(name).trim(),email:String(email).trim().toLowerCase(),passwordHash:await bcrypt.hash(password,12),role,team:String(team).trim()||"General",active:true,createdAt:now()};
  db.users.push(u); await saveDb(); res.status(201).json({user:cleanUser(u)});
});
app.patch("/api/users/:id", auth, adminOnly, async (req,res) => {
  const u=db.users.find(x=>x.id===req.params.id); if(!u) return res.status(404).json({error:"User not found."});
  if(req.body.name) u.name=String(req.body.name).trim();
  if(req.body.team) u.team=String(req.body.team).trim();
  if(typeof req.body.active==="boolean") u.active=req.body.active;
  if(req.body.password) { if(String(req.body.password).length<12) return res.status(400).json({error:"Password must be at least 12 characters."}); u.passwordHash=await bcrypt.hash(String(req.body.password),12); }
  await saveDb(); res.json({user:cleanUser(u)});
});
app.delete("/api/users/:id", auth, adminOnly, async (req,res) => {
  if(req.params.id===req.user.id) return res.status(400).json({error:"You cannot delete your own account."});
  const u=db.users.find(x=>x.id===req.params.id); if(!u) return res.status(404).json({error:"User not found."});
  u.active=false; await saveDb(); res.json({ok:true});
});

app.get("/api/devices", auth, (req,res) => {
  const list=db.devices.filter(d=>req.user.role==="admin"||d.assignedUserIds.includes(req.user.id)).map(d=>({
    id:d.id,name:d.name,phoneDisplay:req.user.role==="admin"?d.displayPhone:maskPhone(d.displayPhone),
    phoneNumberId:req.user.role==="admin"?d.phoneNumberId:undefined,status:d.status,assignedUserIds:d.assignedUserIds
  }));
  res.json(list);
});
app.post("/api/devices", auth, adminOnly, async (req,res) => {
  const {name,phoneNumberId,displayPhone,accessToken,assignedUserIds=[]}=req.body;
  if(!name||!phoneNumberId||!accessToken) return res.status(400).json({error:"Device name, Phone Number ID and access token are required."});
  const validUsers=assignedUserIds.filter(uid=>db.users.some(u=>u.id===uid&&u.active&&u.role==="agent"));
  const d={id:id(),name:String(name).trim(),phoneNumberId:String(phoneNumberId).trim(),displayPhone:String(displayPhone||""),accessToken:String(accessToken),assignedUserIds:validUsers,status:"configured",createdAt:now()};
  db.devices.push(d); await saveDb(); res.status(201).json({id:d.id,name:d.name,status:d.status});
});
app.patch("/api/devices/:id", auth, adminOnly, async (req,res) => {
  const d=db.devices.find(x=>x.id===req.params.id); if(!d) return res.status(404).json({error:"Device not found."});
  if(req.body.name) d.name=String(req.body.name).trim();
  if(req.body.displayPhone!==undefined) d.displayPhone=String(req.body.displayPhone);
  if(req.body.accessToken) d.accessToken=String(req.body.accessToken);
  if(Array.isArray(req.body.assignedUserIds)) d.assignedUserIds=req.body.assignedUserIds.filter(uid=>db.users.some(u=>u.id===uid&&u.active&&u.role==="agent"));
  if(req.body.status) d.status=String(req.body.status);
  await saveDb(); res.json({ok:true});
});
app.delete("/api/devices/:id", auth, adminOnly, async (req,res) => {
  db.devices=db.devices.filter(d=>d.id!==req.params.id);
  db.conversations=db.conversations.filter(c=>c.deviceId!==req.params.id);
  await saveDb(); res.json({ok:true});
});

app.get("/api/conversations", auth, (req,res) => {
  const list=db.conversations.filter(c=>canAccessConversation(req.user,c)).sort((a,b)=>new Date(b.lastMessageAt||b.createdAt)-new Date(a.lastMessageAt||a.createdAt));
  res.json(list.map(c=>visibleConversation(req.user,c)));
});
app.get("/api/conversations/:id/messages", auth, requireConversation, (req,res) => {
  req.conversation.unread=0; saveDb();
  res.json(db.messages.filter(m=>m.conversationId===req.conversation.id).map(m=>({
    id:m.id,direction:m.direction,type:m.type,body:m.body,mediaUrl:m.mediaId?`/api/media/${encodeURIComponent(m.mediaId)}?deviceId=${encodeURIComponent(req.conversation.deviceId)}`:m.mediaUrl,
    createdAt:m.createdAt,status:m.status
  })));
});
app.patch("/api/conversations/:id/assign", auth, adminOnly, requireConversation, async (req,res) => {
  const user=db.users.find(u=>u.id===req.body.userId&&u.active&&u.role==="agent");
  if(!user) return res.status(400).json({error:"Choose an active staff account."});
  const d=db.devices.find(d=>d.id===req.conversation.deviceId);
  if(!d || !d.assignedUserIds.includes(user.id)) return res.status(400).json({error:"Assign this staff member to the device first."});
  req.conversation.assignedTo=user.id; await saveDb(); res.json({ok:true});
});

const upload=multer({dest:UPLOAD_DIR,limits:{fileSize:8*1024*1024},fileFilter:(req,file,cb)=>{
  if(!/^image\/(jpeg|png|webp)$/.test(file.mimetype)) return cb(new Error("Only JPG, PNG and WEBP images are allowed."));
  cb(null,true);
}});
async function sendCloudMessage(device,to,payload) {
  const url=`https://graph.facebook.com/${GRAPH_VERSION}/${device.phoneNumberId}/messages`;
  const response=await axios.post(url,{messaging_product:"whatsapp",recipient_type:"individual",to,...payload},{headers:{Authorization:`Bearer ${device.accessToken}`,"Content-Type":"application/json"},timeout:30000});
  return response.data;
}
app.post("/api/conversations/:id/send", auth, requireConversation, upload.single("image"), async (req,res) => {
  const c=req.conversation, d=deviceForUser(req.user,c.deviceId);
  if(!d) { if(req.file) await fsp.unlink(req.file.path).catch(()=>{}); return res.status(403).json({error:"Device access denied."}); }
  const text=String(req.body.text||"").trim();
  if(!text&&!req.file) return res.status(400).json({error:"Write a message or attach an image."});
  try {
    let payload, type="text", mediaId=null, body=text;
    if(req.file) {
      const form = new (require("form-data"))();
      form.append("messaging_product","whatsapp");
      form.append("file",fs.createReadStream(req.file.path),{filename:req.file.originalname,contentType:req.file.mimetype});
      const media=await axios.post(`https://graph.facebook.com/${GRAPH_VERSION}/${d.phoneNumberId}/media`,form,{headers:{...form.getHeaders(),Authorization:`Bearer ${d.accessToken}`},timeout:30000});
      mediaId=media.data.id; type="image";
      payload={type:"image",image:{id:mediaId,caption:text||undefined}};
    } else payload={type:"text",text:{preview_url:false,body:text}};
    const sent=await sendCloudMessage(d,c.customerPhone,payload);
    const message={id:id(),conversationId:c.id,direction:"out",type,body,mediaId,createdAt:now(),status:"sent",waMessageId:sent.messages?.[0]?.id};
    db.messages.push(message); c.lastMessage=type==="image"?(text||"Image"):text; c.lastMessageAt=message.createdAt; await saveDb();
    res.json({ok:true,message:{id:message.id,direction:message.direction,type:message.type,body:message.body,createdAt:message.createdAt,status:message.status}});
  } catch(e) {
    res.status(502).json({error:e.response?.data?.error?.message||"Meta could not send this message. Check the device token, number and API setup."});
  } finally { if(req.file) await fsp.unlink(req.file.path).catch(()=>{}); }
});

app.get("/api/media/:mediaId", auth, async (req,res) => {
  const device=deviceForUser(req.user,req.query.deviceId);
  if(!device) return res.status(403).end();
  try {
    const meta=await axios.get(`https://graph.facebook.com/${GRAPH_VERSION}/${req.params.mediaId}`,{headers:{Authorization:`Bearer ${device.accessToken}`}});
    const media=await axios.get(meta.data.url,{headers:{Authorization:`Bearer ${device.accessToken}`},responseType:"stream"});
    res.setHeader("Content-Type",media.headers["content-type"]||"application/octet-stream");
    media.data.pipe(res);
  } catch { res.status(404).json({error:"Media unavailable."}); }
});

// Meta webhook verification (configure this URL as https://your-domain/webhook).
app.get("/webhook", (req,res) => {
  const mode=req.query["hub.mode"], token=req.query["hub.verify_token"], challenge=req.query["hub.challenge"];
  if(mode==="subscribe" && token===process.env.META_VERIFY_TOKEN) return res.status(200).send(challenge);
  res.sendStatus(403);
});
app.post("/webhook", express.raw({type:"application/json",limit:"5mb"}), async (req,res) => {
  const raw=req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
  if(process.env.META_APP_SECRET) {
    const signature=req.get("x-hub-signature-256")||"";
    const expected="sha256="+crypto.createHmac("sha256",process.env.META_APP_SECRET).update(raw).digest("hex");
    const a=Buffer.from(signature), b=Buffer.from(expected);
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.sendStatus(401);
  }
  let payload; try { payload=JSON.parse(raw.toString("utf8")); } catch { return res.sendStatus(400); }
  try {
    for(const entry of payload.entry||[]) for(const change of entry.changes||[]) {
      const value=change.value||{};
      const metadata=value.metadata||{};
      const device=db.devices.find(d=>d.phoneNumberId===metadata.phone_number_id);
      if(!device) continue;
      for(const msg of value.messages||[]) {
        const contact=(value.contacts||[]).find(c=>c.wa_id===msg.from);
        let c=db.conversations.find(x=>x.deviceId===device.id&&x.customerPhone===msg.from);
        if(!c) {
          c={id:id(),deviceId:device.id,customerPhone:msg.from,customerName:contact?.profile?.name||"",assignedTo:device.assignedUserIds[0]||null,status:"open",unread:0,createdAt:now()};
          db.conversations.push(c);
        }
        const m={id:id(),conversationId:c.id,direction:"in",type:msg.type||"text",body:msg.text?.body||msg.image?.caption||`[${msg.type||"message"}]`,mediaId:msg.image?.id||msg.document?.id||null,createdAt:new Date(Number(msg.timestamp||Date.now()/1000)*1000).toISOString(),status:"received"};
        db.messages.push(m); c.lastMessage=m.body; c.lastMessageAt=m.createdAt; c.unread=(c.unread||0)+1;
      }
      for(const status of value.statuses||[]) {
        const m=db.messages.find(x=>x.waMessageId===status.id);
        if(m) m.status=status.status;
      }
    }
    await saveDb(); res.sendStatus(200);
  } catch(e) { console.error("Webhook processing error",e); res.sendStatus(500); }
});

app.use((err,req,res,next)=>{ console.error(err.message); res.status(400).json({error:err.message||"Request failed."}); });
loadDb().then(()=>app.listen(PORT,()=>console.log(`WhatsApp Team Desk running at http://localhost:${PORT}`)));
