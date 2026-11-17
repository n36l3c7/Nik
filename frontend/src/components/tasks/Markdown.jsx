import { blocks } from '../../domain/markdown.js'

/*
 * A text written as a small Markdown (domain/markdown.js), drawn as elements:
 * what it says is never read as HTML.
 */

function Inline({ parts }) {
  return parts.map((part, index) => {
    switch (part.type) {
      case 'bold':
        return <strong key={index}>{part.text}</strong>
      case 'italic':
        return <em key={index}>{part.text}</em>
      case 'code':
        return (
          <code key={index} className="bg-canvas px-1 font-mono text-[0.9em]">
            {part.text}
          </code>
        )
      case 'link':
        return (
          <a
            key={index}
            href={part.href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-link underline hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {part.text}
          </a>
        )
      default:
        return <span key={index}>{part.text}</span>
    }
  })
}

const HEADINGS = ['text-base font-semibold', 'text-sm font-semibold', 'text-sm font-medium text-fg-muted']

/** @param {{ text: string, className?: string }} props */
export default function Markdown({ text, className = '' }) {
  const found = blocks(text)
  if (found.length === 0) return null
  return (
    <div className={`flex flex-col gap-2 text-sm leading-relaxed text-fg ${className}`}>
      {found.map((block, index) => {
        if (block.type === 'heading') {
          return (
            <p key={index} role="heading" aria-level={block.level + 2} className={HEADINGS[block.level - 1]}>
              <Inline parts={block.parts} />
            </p>
          )
        }
        if (block.type === 'code') {
          return (
            <pre key={index} className="overflow-x-auto bg-canvas p-2 font-mono text-xs">
              {block.text}
            </pre>
          )
        }
        if (block.type === 'list') {
          const List = block.ordered ? 'ol' : 'ul'
          return (
            <List key={index} className={`ml-5 flex flex-col gap-1 ${block.ordered ? 'list-decimal' : 'list-disc'}`}>
              {block.items.map((parts, at) => (
                <li key={at}>
                  <Inline parts={parts} />
                </li>
              ))}
            </List>
          )
        }
        return (
          <p key={index}>
            <Inline parts={block.parts} />
          </p>
        )
      })}
    </div>
  )
}
