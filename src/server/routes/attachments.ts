import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { requireUser } from '../auth/session.ts';
import { findAttachmentRow, requireGrievance } from '../db/queries.ts';
import { assertCanViewGrievance } from '../db/queries.ts';
import { readStoredFile } from '../storage/attachments.ts';
import { HttpError } from '../http/errors.ts';
import { audit } from '../http/audit.ts';

export const attachmentRoutes = new Hono<AppEnv>();

attachmentRoutes.get('/:id', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = findAttachmentRow(db, c.req.param('id'));
	if (!row) throw new HttpError(404, 'not_found', 'Attachment was not found.');
	const grievance = requireGrievance(db, row.grievance_id);
	try { assertCanViewGrievance(user, grievance); } catch (e) { if (e instanceof HttpError && e.status === 403) audit(c, 'authz.denied', { userId: user.id, role: user.role, resourceId: row.id, reason: 'BOLA_attachment_view', result: 'denied' }); throw e; }
	const bytes = readStoredFile(c.get('uploadsDir'), row.stored_filename);
	c.header('Content-Type', row.mime_type);
	c.header('Content-Length', String(bytes.length));
	c.header('Content-Disposition', `inline; filename="${row.original_filename.replaceAll('"','')}"`);
	return c.body(new Uint8Array(bytes));
});
