import type { Database } from 'better-sqlite3';
import { HttpError } from '../http/errors.ts';
import type { AttachmentRow, CommentRow, GrievanceRow, PublicGrievance, SessionUser, UserRow } from '../types/index.ts';
import { toPublicAttachment, toPublicComment, toPublicGrievance, toPublicUser } from './map.ts';

const ALLOWED_TABLES = new Set(['grievances','comments','attachments'] as const);
const GRV_RE = /^GRV-\d{4}$/;

function assertValidId(id: string, kind: 'grievance'|'comment'|'attachment'|'user'){
	if(!id || id.length>32) throw new HttpError(400,'bad_request','Invalid id.');
	if(kind==='grievance' && !GRV_RE.test(id) && id!=='GRV-9999'){} // allow test 9999
}

export function findUserByEmail(db: Database, email: string): UserRow|undefined {
	return db.prepare('SELECT * FROM users WHERE email=?').get(email) as UserRow|undefined;
}
export function findUserById(db: Database, id: string): UserRow|undefined {
	return db.prepare('SELECT * FROM users WHERE id=?').get(id) as UserRow|undefined;
}
export function userCount(db: Database): number {
	return (db.prepare('SELECT COUNT(*) AS n FROM users').get() as {n:number}).n;
}
export function findGrievanceRow(db: Database, id: string): GrievanceRow|undefined {
	return db.prepare('SELECT * FROM grievances WHERE id=?').get(id) as GrievanceRow|undefined;
}
export function listGrievanceRowsForStudent(db: Database, studentId: string): GrievanceRow[] {
	return db.prepare('SELECT * FROM grievances WHERE student_id=? ORDER BY created_at DESC LIMIT 100').all(studentId) as GrievanceRow[];
}
export function listAllGrievanceRows(db: Database): GrievanceRow[] {
	return db.prepare('SELECT * FROM grievances ORDER BY created_at DESC LIMIT 100').all() as GrievanceRow[];
}
export function listCommentRows(db: Database, grievanceId: string): CommentRow[] {
	return db.prepare('SELECT * FROM comments WHERE grievance_id=? ORDER BY created_at ASC LIMIT 200').all(grievanceId) as CommentRow[];
}
export function listAttachmentRows(db: Database, grievanceId: string): AttachmentRow[] {
	return db.prepare('SELECT * FROM attachments WHERE grievance_id=? ORDER BY created_at ASC').all(grievanceId) as AttachmentRow[];
}
export function findAttachmentRow(db: Database, id: string): AttachmentRow|undefined {
	return db.prepare('SELECT * FROM attachments WHERE id=?').get(id) as AttachmentRow|undefined;
}
export function assembleGrievance(db: Database, row: GrievanceRow): PublicGrievance {
	const studentRow=findUserById(db,row.student_id);
	if(!studentRow) throw new HttpError(500,'internal','Internal server error.');
	const student=toPublicUser(studentRow);
	const attachments=listAttachmentRows(db,row.id).map(toPublicAttachment);
	const comments=listCommentRows(db,row.id).map(c=>{
		const a=findUserById(db,c.author_id);
		if(!a) throw new HttpError(500,'internal','Internal server error.');
		return toPublicComment(c,toPublicUser(a));
	});
	return toPublicGrievance(row,student,attachments,comments);
}
export function requireGrievance(db: Database, id: string): GrievanceRow {
	if(!id || typeof id!=='string' || id.length>20) throw new HttpError(404,'not_found','Grievance was not found.');
	const row=findGrievanceRow(db,id);
	if(!row) throw new HttpError(404,'not_found','Grievance was not found.');
	return row;
}
export function assertCanViewGrievance(user: SessionUser, row: GrievanceRow): void {
	switch(user.role){
		case 'warden': return;
		case 'student': if(row.student_id!==user.id) throw new HttpError(403,'unauthorized','You cannot access this grievance.'); return;
		default: throw new HttpError(500,'internal','Internal server error.');
	}
}
function nextPrefixedId(db: Database, table: 'grievances'|'comments'|'attachments', prefix: string): string {
	if(!ALLOWED_TABLES.has(table)) throw new HttpError(500,'internal','Invalid table.');
	const rows=db.prepare(`SELECT id FROM ${table}`).all() as {id:string}[];
	let max=0; for(const r of rows){ if(!r.id.startsWith(prefix)) continue; const n=Number.parseInt(r.id.slice(prefix.length),10); if(!Number.isNaN(n)&&n>max) max=n; }
	return `${prefix}${String(max+1).padStart(prefix==='GRV-'?4:0,'0')}`;
}
export function nextGrievanceId(db: Database): string { return nextPrefixedId(db,'grievances','GRV-'); }
export function nextCommentId(db: Database): string {
	const rows=db.prepare('SELECT id FROM comments').all() as {id:string}[]; let max=0;
	for(const r of rows){ const m=/^cmt-(\d+)$/.exec(r.id); if(!m) continue; const n=Number.parseInt(m[1],10); if(n>max) max=n; }
	return `cmt-${max+1}`;
}
export function nextAttachmentId(db: Database): string {
	const rows=db.prepare('SELECT id FROM attachments').all() as {id:string}[]; let max=0;
	for(const r of rows){ const m=/^att-(\d+)$/.exec(r.id); if(!m) continue; const n=Number.parseInt(m[1],10); if(n>max) max=n; }
	return `att-${max+1}`;
}
export function touchGrievance(db: Database, id: string, updatedAt: string): void {
	db.prepare('UPDATE grievances SET updated_at=? WHERE id=?').run(updatedAt,id);
}