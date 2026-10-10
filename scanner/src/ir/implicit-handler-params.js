// Implicit request-bound handler parameters (QA-006, mechanism "framework entry points").
//
// A web framework binds the parameters of a request-handler method from the
// request WITHOUT any annotation on the parameter itself:
//   - ASP.NET MVC / Core: a public action method of a controller binds `string next`
//     from the route, query string or form unless it carries `[FromServices]`.
//   - Spring MVC: a method carrying `@GetMapping` / `@RequestMapping` / ... binds a plain
//     `String q` parameter from the request parameters (`@RequestParam` is optional).
//
// The taint engine's annotation channel (`fn.paramAnnotations`, matched by the catalog's
// `type: 'annotation'` sources) only ever saw the EXPLICIT forms (`[FromQuery]`,
// `@RequestParam`), so a handler written in the equally common implicit form had no
// source at all and the flow was invisible to the taint layer. This module is the pure
// decision of "is this parameter implicitly request-bound", shared by the C# and Java
// frontends; each frontend turns a positive answer into a `paramAnnotations` entry whose
// decorator is one of the two names below, which the catalog binds to a source.
//
// Scope, stated so nothing is over-read:
//   - ONLY string-shaped parameters. A numeric or Guid parameter cannot carry an injection
//     payload, and a complex model parameter's field-level taint is out of scope here.
//   - ONLY inside a class the framework would treat as a handler (a Controller-derived
//     class, or any class whose name ends in `Controller`; for Spring, the MAPPING
//     annotation on the method is what makes it a handler, not the class).
//   - A DI-injected parameter is not request-bound: `[FromServices]` opts a parameter out.
//   - Nothing here looks at a file name, path, comment or label.

export const IMPLICIT_MVC_PARAM = 'ImplicitMvcActionParam';
export const IMPLICIT_SPRING_PARAM = 'ImplicitSpringMappedParam';

const CS_CONTROLLER_BASE = /^(?:Controller|ControllerBase|ApiController|AsyncController)$/;
const CS_STRINGISH = /^(?:(?:System\.)?[Ss]tring\??(?:\[\])?|(?:List|IList|IEnumerable|ICollection|IReadOnlyList)<\s*(?:System\.)?[Ss]tring\??\s*>)$/;
const CS_DI_OPT_OUT = new Set(['FromServices', 'FromKeyedServices']);

/** True when a C# class record (`{ name, bases }`) is one the framework treats as a controller. */
function isCsControllerClass(range) {
  if (!range) return false;
  if (/Controller$/.test(range.name || '')) return true;
  return (range.bases || []).some((b) => CS_CONTROLLER_BASE.test(b));
}

/**
 * Should a C# parameter be treated as implicitly request-bound?
 * @param {object} o
 * @param {string} o.modifiers   the method's modifier text (the declaration prefix), e.g. 'public async'
 * @param {string} o.rawType     the parameter's declared type text, e.g. 'string', 'List<string>'
 * @param {string[]} o.decorators the parameter's attribute names
 * @param {boolean} o.nonAction  the method carries [NonAction]
 * @param {object} o.classRange  the enclosing class record
 */
export function isImplicitCsActionParam({ modifiers = '', rawType = '', decorators = [], nonAction = false, classRange = null }) {
  if (nonAction) return false;
  if (!isCsControllerClass(classRange)) return false;
  if (!/\bpublic\b/.test(modifiers) || /\bstatic\b/.test(modifiers)) return false;
  if (decorators.some((d) => CS_DI_OPT_OUT.has(d))) return false;
  // An explicit binding attribute is handled by the explicit annotation sources.
  if (decorators.some((d) => /^From/.test(d))) return false;
  return CS_STRINGISH.test(String(rawType).trim());
}

const SPRING_MAPPING = /^(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)$/;
const SPRING_DI_OR_BINDING = /^(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestAttribute|SessionAttribute|RequestPart|Value|Autowired)$/;

/**
 * Should a Java parameter be treated as implicitly request-bound?
 * @param {string[]} o.methodAnnotations annotation simple names on the method
 * @param {string} o.paramType   the parameter's simple type name ('String')
 * @param {string[]} o.decorators annotation names already on the parameter
 */
export function isImplicitSpringMappedParam({ methodAnnotations = [], paramType = '', decorators = [] }) {
  if (!methodAnnotations.some((a) => SPRING_MAPPING.test(a))) return false;
  if (paramType !== 'String') return false;
  if (decorators.some((d) => SPRING_DI_OR_BINDING.test(d))) return false;
  return true;
}
