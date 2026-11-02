// A problem found in several places has one command per place. The steps
// show the shared part once; the commands that differ go in a list with
// one entry per place (and a Copy all).

// Commands (with a space, or long) get their own line; short names stay inline.
export const isBlock = code => code.includes(' ') || code.length > 32

export const codesOf = f => [...(f.fix || '').matchAll(/`([^`]+)`/g)].map(m => m[1]).filter(isBlock)

// Where a finding is: the part of its title after ": ", else the item's path.
export const placeOf = x =>
  x.title.includes(': ')
    ? x.title.slice(x.title.indexOf(': ') + 2)
    : x.place || x.title

// perPlace returns null when every place shares the same commands, else
// { hide: Set of commands to leave out of the steps, places: [{ place, cmds }] }.
export function perPlace(all) {
  if (all.length < 2) return null
  if (all[0].plan) {
    return { hide: new Set(), places: all.map(x => ({ place: placeOf(x), cmds: x.plan || [] })), plan: true }
  }
  const lists = all.map(codesOf)
  const shared = lists[0].filter(c => lists.every(l => l.includes(c)))
  const differ = lists.map(l => l.filter(c => !shared.includes(c)))
  if (!differ[0].length) return null
  return { hide: new Set(differ[0]), places: all.map((x, i) => ({ place: placeOf(x), cmds: differ[i] })) }
}
