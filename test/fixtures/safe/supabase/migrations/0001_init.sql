create table public.profiles (
  id uuid primary key default uuid_generate_v4(),
  owner_id uuid not null,
  email text not null,
  created_at timestamptz default now()
);

alter table public.profiles enable row level security;

create policy "profiles: owner can read own row"
  on public.profiles
  for select
  using (owner_id = auth.uid());

create policy "profiles: owner can update own row"
  on public.profiles
  for update
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

create table public.posts (
  id uuid primary key default uuid_generate_v4(),
  author_id uuid not null,
  body text,
  created_at timestamptz default now()
);

alter table public.posts enable row level security;

create policy "posts: owner can read own posts"
  on public.posts
  for select
  using (author_id = auth.uid());
