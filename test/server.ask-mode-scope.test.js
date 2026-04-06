const request = require('supertest');

const loadApp = () => {
  jest.resetModules();
  return require('../server');
};

describe('ask-mode scope guard', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    delete global.fetch;
  });

  test('blocks non-Postman ask intent before model call', async () => {
    const app = loadApp();
    const res = await request(app)
      .post('/api/agent')
      .send({
        provider: 'groq',
        model: 'groq/compound-mini',
        context: {
          current_mode: 'ask',
          user_message: 'write me an essay on good vibes',
          chat_goal: 'write me an essay on good vibes',
          conversation_history: [],
          current_request: {
            method: 'GET',
            url: 'https://example.com',
            headers: [],
            params: [],
            body: ''
          },
          last_response: null,
          current_assertions: []
        }
      });

    expect(res.status).toBe(200);
    expect(res.body.actions).toEqual([]);
    expect(String(res.body.message || '')).toMatch(/intended only for postman-centric api tasks/i);
    expect(res.body.diagnostics?.blocked).toBe(true);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('layer-2 validator allows API debugging ask intents', () => {
    const app = loadApp();
    const verdict = app.__internals.evaluateAskIntent({
      current_mode: 'ask',
      user_message: 'help debug this API request: GET /users returns 401, what auth header is missing?',
      chat_goal: 'debug API auth issue'
    });

    expect(verdict.allowed).toBe(true);
    expect(verdict.reason).toBe('postman_intent_detected');
  });
});
