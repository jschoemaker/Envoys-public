import type { FastifyInstance } from 'fastify'

const RESEND_API_KEY   = process.env.RESEND_API_KEY   ?? ''
const RESEND_AUDIENCE_ID = process.env.RESEND_AUDIENCE_ID ?? ''

export async function waitlistRoutes(app: FastifyInstance) {
  app.post('/waitlist', async (req, reply) => {
    const { email } = req.body as { email?: string }

    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return reply.code(400).send({ error: 'Valid email required' })
    }

    if (!RESEND_API_KEY || !RESEND_AUDIENCE_ID) {
      console.log(`[Waitlist] New signup: ${email}`)
      return reply.send({ ok: true })
    }

    try {
      const res = await fetch(`https://api.resend.com/audiences/${RESEND_AUDIENCE_ID}/contacts`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, unsubscribed: false }),
      })

      if (!res.ok) {
        const err = await res.text()
        // If already on list, still return success — no need to alarm the user
        if (res.status === 409) return reply.send({ ok: true })
        console.error(`[Waitlist] Resend error for ${email}: ${err}`)
        return reply.code(500).send({ error: 'Failed to join waitlist' })
      }

      console.log(`[Waitlist] Added ${email} to audience`)
      return reply.send({ ok: true })
    } catch (err) {
      console.error(`[Waitlist] Error for ${email}:`, err)
      return reply.code(500).send({ error: 'Failed to join waitlist' })
    }
  })
}
