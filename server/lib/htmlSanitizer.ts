import sanitizeHtml from 'sanitize-html';

const ALLOWED_TAGS = ['p','br','strong','em','u','s','ol','ul','li','pre','code','a','img','h1','h2','h3','blockquote'];
const ALLOWED_ATTRS: sanitizeHtml.IOptions['allowedAttributes'] = {
  a: ['href','title','target','rel'],
  img: ['src','alt','width','height'],
};

// img src must point to our image endpoint
const IMG_SRC_ALLOWLIST = /^\/api\/v1\/action-plans\/images\/[a-f0-9-]+\.(png|jpe?g|gif|webp)$/i;

export function sanitizeActionPlanHtml(input: string): string {
  return sanitizeHtml(input, {
    allowedTags: ALLOWED_TAGS,
    allowedAttributes: ALLOWED_ATTRS,
    allowedSchemes: ['http','https','mailto'],
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }),
    },
    exclusiveFilter: (frame) => {
      if (frame.tag === 'img' && !IMG_SRC_ALLOWLIST.test(frame.attribs.src ?? '')) return true;
      return false;
    },
  });
}
